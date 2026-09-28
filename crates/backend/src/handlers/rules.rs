use axum::{
    extract::{Path, State},
    Json,
};
use common::models::{CreateRuleDto, DetectionRule, UpdateRuleDto};
use common::ApiResponse;
use uuid::Uuid;
use validator::Validate;

use crate::{
    auth::{middleware::CurrentUser, rbac::require_admin},
    error::AppError,
    state::AppState,
};

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
    let rules = sqlx::query_as::<_, DetectionRule>(
        r#"
        SELECT 
            id, name, rule_type, condition_json, severity, is_enabled,
            threshold_value, time_window_seconds, created_at, updated_at
        FROM detection_rules
        ORDER BY created_at ASC
        "#,
    )
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
    let rule = sqlx::query_as::<_, DetectionRule>(
        r#"
        SELECT 
            id, name, rule_type, condition_json, severity, is_enabled,
            threshold_value, time_window_seconds, created_at, updated_at
        FROM detection_rules
        WHERE id = $1
        "#,
    )
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
        (status = 403, description = "Admin role required", body = ApiResponse<()>)
    ),
    tag = "Rules",
    security(("bearer_auth" = []))
)]
pub async fn create_rule(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Json(payload): Json<CreateRuleDto>,
) -> Result<Json<ApiResponse<DetectionRule>>, AppError> {
    require_admin(&current_user)?;
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let is_enabled = payload.is_enabled.unwrap_or(true);

    let rule = sqlx::query_as::<_, DetectionRule>(
        r#"
        INSERT INTO detection_rules (name, rule_type, condition_json, severity, is_enabled, threshold_value, time_window_seconds)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING 
            id, name, rule_type, condition_json, severity, is_enabled,
            threshold_value, time_window_seconds, created_at, updated_at
        "#
    )
    .bind(&payload.name)
    .bind(payload.rule_type)
    .bind(&payload.condition_json)
    .bind(payload.severity)
    .bind(is_enabled)
    .bind(payload.threshold_value)
    .bind(payload.time_window_seconds)
    .fetch_one(&state.pool)
    .await?;

    let _ = sqlx::query!(
        "INSERT INTO audit_logs (user_id, action, target) VALUES ($1, $2, $3)",
        current_user.0.sub,
        "CREATE_RULE",
        rule.name
    )
    .execute(&state.pool)
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
        (status = 403, description = "Admin role required", body = ApiResponse<()>)
    ),
    tag = "Rules",
    security(("bearer_auth" = []))
)]
pub async fn update_rule(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateRuleDto>,
) -> Result<Json<ApiResponse<DetectionRule>>, AppError> {
    require_admin(&current_user)?;

    let _existing = sqlx::query_as::<_, DetectionRule>(
        "SELECT id, name, rule_type, condition_json, severity, is_enabled, threshold_value, time_window_seconds, created_at, updated_at FROM detection_rules WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Detection rule {} not found", id)))?;

    let updated = sqlx::query_as::<_, DetectionRule>(
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
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $8
        RETURNING 
            id, name, rule_type, condition_json, severity, is_enabled,
            threshold_value, time_window_seconds, created_at, updated_at
        "#,
    )
    .bind(payload.name)
    .bind(payload.rule_type)
    .bind(payload.condition_json)
    .bind(payload.severity)
    .bind(payload.is_enabled)
    .bind(payload.threshold_value)
    .bind(payload.time_window_seconds)
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    let _ = sqlx::query!(
        "INSERT INTO audit_logs (user_id, action, target) VALUES ($1, $2, $3)",
        current_user.0.sub,
        "UPDATE_RULE",
        updated.name
    )
    .execute(&state.pool)
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
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    require_admin(&current_user)?;

    let rows_affected = sqlx::query!("DELETE FROM detection_rules WHERE id = $1", id)
        .execute(&state.pool)
        .await?
        .rows_affected();

    if rows_affected == 0 {
        return Err(AppError::NotFound(format!("Rule {} not found", id)));
    }

    let _ = sqlx::query!(
        "INSERT INTO audit_logs (user_id, action, target) VALUES ($1, $2, $3)",
        current_user.0.sub,
        "DELETE_RULE",
        id.to_string()
    )
    .execute(&state.pool)
    .await;

    Ok(Json(ApiResponse::ok(format!(
        "Rule {} deleted successfully",
        id
    ))))
}
