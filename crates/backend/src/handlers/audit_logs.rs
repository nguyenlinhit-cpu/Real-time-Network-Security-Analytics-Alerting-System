use axum::{
    extract::{Query, State},
    Json,
};
use common::models::AuditLog;
use common::ApiResponse;
use serde::Deserialize;

use crate::{
    auth::{middleware::CurrentUser, rbac::require_admin},
    error::AppError,
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub action: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/audit-logs",
    params(
        ("action" = Option<String>, Query, description = "Filter by action keyword"),
        ("limit" = Option<i64>, Query, description = "Maximum number of logs (default 50)"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination (default 0)")
    ),
    responses(
        (status = 200, description = "List of security audit logs", body = ApiResponse<Vec<AuditLog>>),
        (status = 403, description = "Admin permissions required", body = ApiResponse<()>)
    ),
    tag = "Audit",
    security(("bearer_auth" = []))
)]
pub async fn get_audit_logs(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<ApiResponse<Vec<AuditLog>>>, AppError> {
    require_admin(&current_user)?;

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let action_filter = query.action.as_ref().map(|a| format!("%{}%", a));

    let logs = sqlx::query_as::<_, AuditLog>(
        r#"
        SELECT id, user_id, action, target, timestamp, ip_address
        FROM audit_logs
        WHERE ($1::TEXT IS NULL OR action ILIKE $1 OR target ILIKE $1)
        ORDER BY timestamp DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(action_filter)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(ApiResponse::ok(logs)))
}
