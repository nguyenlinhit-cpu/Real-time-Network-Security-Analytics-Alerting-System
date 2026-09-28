use axum::{
    extract::{Path, State},
    Json,
};
use common::models::{Alert, AlertStatus, UpdateAlertDto};
use common::ApiResponse;
use uuid::Uuid;

use crate::{
    auth::{middleware::CurrentUser, rbac::require_analyst_or_admin},
    error::AppError,
    state::AppState,
};

#[utoipa::path(
    get,
    path = "/api/alerts",
    responses(
        (status = 200, description = "List of security alerts", body = ApiResponse<Vec<Alert>>)
    ),
    tag = "Alerts",
    security(("bearer_auth" = []))
)]
pub async fn get_alerts(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Alert>>>, AppError> {
    let alerts = sqlx::query_as::<_, Alert>(
        r#"
        SELECT 
            id, rule_id, severity, title, description, src_ip, dst_ip,
            detected_at, status, acknowledged_by, resolved_at
        FROM alerts
        ORDER BY detected_at DESC
        LIMIT 100
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(ApiResponse::ok(alerts)))
}

#[utoipa::path(
    get,
    path = "/api/alerts/{id}",
    params(
        ("id" = Uuid, Path, description = "Alert UUID identifier")
    ),
    responses(
        (status = 200, description = "Alert details", body = ApiResponse<Alert>),
        (status = 404, description = "Alert not found", body = ApiResponse<()>)
    ),
    tag = "Alerts",
    security(("bearer_auth" = []))
)]
pub async fn get_alert_by_id(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<Alert>>, AppError> {
    let alert = sqlx::query_as::<_, Alert>(
        r#"
        SELECT 
            id, rule_id, severity, title, description, src_ip, dst_ip,
            detected_at, status, acknowledged_by, resolved_at
        FROM alerts
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Alert with ID {} not found", id)))?;

    Ok(Json(ApiResponse::ok(alert)))
}

#[utoipa::path(
    patch,
    path = "/api/alerts/{id}",
    request_body = UpdateAlertDto,
    params(
        ("id" = Uuid, Path, description = "Alert UUID identifier")
    ),
    responses(
        (status = 200, description = "Alert status updated", body = ApiResponse<Alert>),
        (status = 403, description = "Insufficient role permissions", body = ApiResponse<()>)
    ),
    tag = "Alerts",
    security(("bearer_auth" = []))
)]
pub async fn update_alert_status(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateAlertDto>,
) -> Result<Json<ApiResponse<Alert>>, AppError> {
    require_analyst_or_admin(&current_user)?;

    // OWASP Access Control: Verify resource ownership
    let existing = sqlx::query_as::<_, Alert>(
        "SELECT id, rule_id, severity, title, description, src_ip, dst_ip, detected_at, status, acknowledged_by, resolved_at FROM alerts WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Alert with ID {} not found", id)))?;

    if let Some(owner) = existing.acknowledged_by {
        if owner != current_user.0.sub && current_user.0.role != common::models::UserRole::Admin {
            return Err(AppError::Forbidden(
                "This incident is assigned to another analyst. Only an Administrator can override or resolve it.".to_string(),
            ));
        }
    }

    let now = chrono::Utc::now();
    let is_resolved = payload.status == AlertStatus::Resolved;
    let resolved_at = if is_resolved { Some(now) } else { None };

    let updated_alert = sqlx::query_as::<_, Alert>(
        r#"
        UPDATE alerts
        SET 
            status = $1,
            acknowledged_by = $2,
            resolved_at = $3
        WHERE id = $4
        RETURNING 
            id, rule_id, severity, title, description, src_ip, dst_ip,
            detected_at, status, acknowledged_by, resolved_at
        "#,
    )
    .bind(payload.status)
    .bind(current_user.0.sub)
    .bind(resolved_at)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Alert with ID {} not found", id)))?;

    // Record audit log
    let _ = sqlx::query!(
        "INSERT INTO audit_logs (user_id, action, target) VALUES ($1, $2, $3)",
        current_user.0.sub,
        format!("UPDATE_ALERT_STATUS:{:?}", payload.status),
        id.to_string()
    )
    .execute(&state.pool)
    .await;

    Ok(Json(ApiResponse::ok(updated_alert)))
}
