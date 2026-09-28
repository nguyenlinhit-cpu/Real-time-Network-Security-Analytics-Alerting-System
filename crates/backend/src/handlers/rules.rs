use axum::{
    extract::{Path, State},
    Json,
};
use common::models::{CreateRuleDto, DetectionRule, UpdateRuleDto};
use common::ApiResponse;
use uuid::Uuid;
use validator::Validate;

use crate::{
    audit,
    auth::{middleware::CurrentUser, rbac::require_admin},
    error::AppError,
    middleware::ClientIp,
    state::AppState,
};

const RULE_COLUMNS: &str = "id, name, rule_type, condition_json, severity, is_enabled, \
     threshold_value, time_window_seconds, created_at, updated_at, mitre_tactic, mitre_technique";

fn map_rule_write_error(e: sqlx::Error) -> AppError {
    match e {
        sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
            AppError::BadRequest("A detection rule with this name already exists".to_string())
        }
        sqlx::Error::Database(ref db_err) if db_err.is_check_violation() => AppError::BadRequest(
            "Invalid rule values: threshold must be >= 0 and time window > 0".to_string(),
        ),
        _ => AppError::DatabaseError(e),
    }
}

/// Empty strings from the UI mean "no MITRE mapping".
fn normalize_mitre(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

#[utoipa::path(
    get,
    path = "/api/rules",
    responses(
        (status = 200, description = "List of detection rules", body = ApiResponse<Vec<DetectionRule>>)
    ),
    tag = "Rules",
    security(("bearer_auth" = []))
)]
pub async fn get_rules(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<DetectionRule>>>, AppError> {
    let rules = sqlx::query_as::<_, DetectionRule>(&format!(
        "SELECT {} FROM detection_rules ORDER BY created_at ASC, name ASC",
        RULE_COLUMNS
    ))
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(ApiResponse::ok(rules)))
}

#[utoipa::path(
    get,
    path = "/api/rules/{id}",
    params(
        ("id" = Uuid, Path, description = "Rule UUID identifier")
    ),
    responses(
        (status = 200, description = "Rule details", body = ApiResponse<DetectionRule>),
        (status = 404, description = "Rule not found", body = ApiResponse<()>)
    ),
    tag = "Rules",
    security(("bearer_auth" = []))
)]
pub async fn get_rule_by_id(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<DetectionRule>>, AppError> {
    let rule = sqlx::query_as::<_, DetectionRule>(&format!(
        "SELECT {} FROM detection_rules WHERE id = $1",
        RULE_COLUMNS
    ))
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Detection rule {} not found", id)))?;

    Ok(Json(ApiResponse::ok(rule)))
}

#[utoipa::path(
    post,
    path = "/api/rules",
    request_body = CreateRuleDto,
    responses(
        (status = 200, description = "Rule created successfully", body = ApiResponse<DetectionRule>),
        (status = 400, description = "Invalid or duplicate rule", body = ApiResponse<()>),
        (status = 403, description = "Admin role required", body = ApiResponse<()>)
    ),
    tag = "Rules",
    security(("bearer_auth" = []))
)]
pub async fn create_rule(
    State(state): State<AppState>,
    current_user: CurrentUser,
    client_ip: ClientIp,
    Json(payload): Json<CreateRuleDto>,
) -> Result<Json<ApiResponse<DetectionRule>>, AppError> {
    require_admin(&current_user)?;
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let is_enabled = payload.is_enabled.unwrap_or(true);

    let rule = sqlx::query_as::<_, DetectionRule>(&format!(
        r#"
        INSERT INTO detection_rules (name, rule_type, condition_json, severity, is_enabled,
            threshold_value, time_window_seconds, mitre_tactic, mitre_technique)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING {}
        "#,
        RULE_COLUMNS
    ))
    .bind(payload.name.trim())
    .bind(payload.rule_type)
    .bind(&payload.condition_json)
    .bind(payload.severity)
    .bind(is_enabled)
    .bind(payload.threshold_value)
    .bind(payload.time_window_seconds)
    .bind(normalize_mitre(payload.mitre_tactic))
    .bind(normalize_mitre(payload.mitre_technique))
    .fetch_one(&state.pool)
    .await
    .map_err(map_rule_write_error)?;

    audit::record(
        &state.pool,
        Some(current_user.0.sub),
        "CREATE_RULE",
        &rule.name,
        Some(client_ip.network()),
    )
    .await;

    Ok(Json(ApiResponse::ok(rule)))
}

#[utoipa::path(
    patch,
    path = "/api/rules/{id}",
    request_body = UpdateRuleDto,
    params(
        ("id" = Uuid, Path, description = "Rule UUID identifier")
    ),
    responses(
        (status = 200, description = "Rule updated successfully", body = ApiResponse<DetectionRule>),
        (status = 400, description = "Invalid rule values", body = ApiResponse<()>),
        (status = 403, description = "Admin role required", body = ApiResponse<()>),
        (status = 404, description = "Rule not found", body = ApiResponse<()>)
    ),
    tag = "Rules",
    security(("bearer_auth" = []))
)]
pub async fn update_rule(
    State(state): State<AppState>,
    current_user: CurrentUser,
    client_ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateRuleDto>,
) -> Result<Json<ApiResponse<DetectionRule>>, AppError> {
    require_admin(&current_user)?;
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    // Missing MITRE fields keep their value; an explicit empty string clears them.
    let set_tactic = payload.mitre_tactic.is_some();
    let set_technique = payload.mitre_technique.is_some();

    let updated = sqlx::query_as::<_, DetectionRule>(&format!(
        r#"
        UPDATE detection_rules
        SET
            name = COALESCE($1, name),
            rule_type = COALESCE($2, rule_type),
            condition_json = COALESCE($3, condition_json),
            severity = COALESCE($4, severity),
            is_enabled = COALESCE($5, is_enabled),
            threshold_value = COALESCE($6, threshold_value),
            time_window_seconds = COALESCE($7, time_window_seconds),
            mitre_tactic = CASE WHEN $8 THEN $9 ELSE mitre_tactic END,
            mitre_technique = CASE WHEN $10 THEN $11 ELSE mitre_technique END,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $12
        RETURNING {}
        "#,
        RULE_COLUMNS
    ))
    .bind(payload.name.map(|n| n.trim().to_string()))
    .bind(payload.rule_type)
    .bind(payload.condition_json)
    .bind(payload.severity)
    .bind(payload.is_enabled)
    .bind(payload.threshold_value)
    .bind(payload.time_window_seconds)
    .bind(set_tactic)
    .bind(normalize_mitre(payload.mitre_tactic))
    .bind(set_technique)
    .bind(normalize_mitre(payload.mitre_technique))
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(map_rule_write_error)?
    .ok_or_else(|| AppError::NotFound(format!("Detection rule {} not found", id)))?;

    audit::record(
        &state.pool,
        Some(current_user.0.sub),
        "UPDATE_RULE",
        &updated.name,
        Some(client_ip.network()),
    )
    .await;

    Ok(Json(ApiResponse::ok(updated)))
}

#[utoipa::path(
    delete,
    path = "/api/rules/{id}",
    params(
        ("id" = Uuid, Path, description = "Rule UUID identifier")
    ),
    responses(
        (status = 200, description = "Rule deleted successfully", body = ApiResponse<String>),
        (status = 403, description = "Admin role required", body = ApiResponse<()>)
    ),
    tag = "Rules",
    security(("bearer_auth" = []))
)]
pub async fn delete_rule(
    State(state): State<AppState>,
    current_user: CurrentUser,
    client_ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    require_admin(&current_user)?;

    let name: String =
        sqlx::query_scalar("DELETE FROM detection_rules WHERE id = $1 RETURNING name")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Rule {} not found", id)))?;

    audit::record(
        &state.pool,
        Some(current_user.0.sub),
        "DELETE_RULE",
        &name,
        Some(client_ip.network()),
    )
    .await;

    Ok(Json(ApiResponse::ok(format!(
        "Rule '{}' deleted successfully",
        name
    ))))
}
