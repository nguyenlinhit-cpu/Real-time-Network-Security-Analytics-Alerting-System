use axum::{
    extract::{Path, State},
    Json,
};
use common::models::{BlockedIp, CreateBlockedIpDto};
use common::ApiResponse;
use ipnetwork::IpNetwork;
use uuid::Uuid;
use validator::Validate;

use crate::{
    auth::{middleware::CurrentUser, rbac::require_admin},
    error::AppError,
    state::AppState,
};

#[utoipa::path(
    get,
    path = "/api/blocklist",
    responses(
        (status = 200, description = "List of blocked IP addresses", body = ApiResponse<Vec<BlockedIp>>)
    ),
    tag = "Blocklist",
    security(("bearer_auth" = []))
)]
pub async fn get_blocklist(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<BlockedIp>>>, AppError> {
    let list = sqlx::query_as::<_, BlockedIp>(
        r#"
        SELECT id, ip_address, reason, blocked_at, blocked_until
        FROM blocked_ips
        ORDER BY blocked_at DESC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(ApiResponse::ok(list)))
}

#[utoipa::path(
    post,
    path = "/api/blocklist",
    request_body = CreateBlockedIpDto,
    responses(
        (status = 200, description = "IP blocked successfully", body = ApiResponse<BlockedIp>),
        (status = 403, description = "Admin role required", body = ApiResponse<()>)
    ),
    tag = "Blocklist",
    security(("bearer_auth" = []))
)]
pub async fn add_to_blocklist(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Json(payload): Json<CreateBlockedIpDto>,
) -> Result<Json<ApiResponse<BlockedIp>>, AppError> {
    require_admin(&current_user)?;
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let ip: IpNetwork = payload
        .ip_address
        .parse()
        .map_err(|e| AppError::BadRequest(format!("Invalid IP address format: {}", e)))?;

    let blocked_until = payload
        .duration_seconds
        .map(|secs| chrono::Utc::now() + chrono::Duration::seconds(secs));

    let entry = sqlx::query_as::<_, BlockedIp>(
        r#"
        INSERT INTO blocked_ips (ip_address, reason, blocked_until)
        VALUES ($1, $2, $3)
        RETURNING id, ip_address, reason, blocked_at, blocked_until
        "#,
    )
    .bind(ip)
    .bind(&payload.reason)
    .bind(blocked_until)
    .fetch_one(&state.pool)
    .await?;

    // Record audit log
    let _ = sqlx::query!(
        "INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES ($1, $2, $3, $4)",
        current_user.0.sub,
        "BLOCK_IP",
        payload.reason,
        ip
    )
    .execute(&state.pool)
    .await;

    Ok(Json(ApiResponse::ok(entry)))
}

#[utoipa::path(
    delete,
    path = "/api/blocklist/{id}",
    params(
        ("id" = Uuid, Path, description = "Blocked IP record UUID")
    ),
    responses(
        (status = 200, description = "IP unblocked successfully", body = ApiResponse<String>),
        (status = 403, description = "Admin role required", body = ApiResponse<()>)
    ),
    tag = "Blocklist",
    security(("bearer_auth" = []))
)]
pub async fn remove_from_blocklist(
    State(state): State<AppState>,
    current_user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    require_admin(&current_user)?;

    let rows_affected = sqlx::query!("DELETE FROM blocked_ips WHERE id = $1", id)
        .execute(&state.pool)
        .await?
        .rows_affected();

    if rows_affected == 0 {
        return Err(AppError::NotFound(format!(
            "Blocklist entry {} not found",
            id
        )));
    }

    let _ = sqlx::query!(
        "INSERT INTO audit_logs (user_id, action, target) VALUES ($1, $2, $3)",
        current_user.0.sub,
        "UNBLOCK_IP",
        id.to_string()
    )
    .execute(&state.pool)
    .await;

    Ok(Json(ApiResponse::ok(format!(
        "IP block entry {} removed",
        id
    ))))
}
