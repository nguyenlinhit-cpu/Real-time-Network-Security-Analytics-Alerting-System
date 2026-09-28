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
    audit,
    auth::{middleware::CurrentUser, rbac::require_admin},
    error::AppError,
    middleware::ClientIp,
    state::AppState,
};

/// Widest networks that may be blocked in one entry. Anything broader (e.g. `0.0.0.0/0`)
/// would cut off large parts of the Internet and is almost certainly a mistake.
const MIN_IPV4_PREFIX: u8 = 16;
const MIN_IPV6_PREFIX: u8 = 48;

pub fn validate_block_target(ip: &IpNetwork) -> Result<(), AppError> {
    let (prefix, min) = match ip {
        IpNetwork::V4(n) => (n.prefix(), MIN_IPV4_PREFIX),
        IpNetwork::V6(n) => (n.prefix(), MIN_IPV6_PREFIX),
    };
    if prefix < min {
        return Err(AppError::BadRequest(format!(
            "Refusing to block {}: networks wider than /{} are not allowed",
            ip, min
        )));
    }
    let addr = ip.ip();
    if addr.is_unspecified() || addr.is_loopback() || addr.is_multicast() {
        return Err(AppError::BadRequest(format!(
            "Refusing to block reserved address {}",
            ip
        )));
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/blocklist",
    responses(
        (status = 200, description = "List of currently active blocked IP addresses", body = ApiResponse<Vec<BlockedIp>>)
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
        WHERE blocked_until IS NULL OR blocked_until > NOW()
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
        (status = 400, description = "Invalid address or duration", body = ApiResponse<()>),
        (status = 403, description = "Admin role required", body = ApiResponse<()>)
    ),
    tag = "Blocklist",
    security(("bearer_auth" = []))
)]
pub async fn add_to_blocklist(
    State(state): State<AppState>,
    current_user: CurrentUser,
    client_ip: ClientIp,
    Json(payload): Json<CreateBlockedIpDto>,
) -> Result<Json<ApiResponse<BlockedIp>>, AppError> {
    require_admin(&current_user)?;
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let ip: IpNetwork = payload
        .ip_address
        .trim()
        .parse()
        .map_err(|e| AppError::BadRequest(format!("Invalid IP address format: {}", e)))?;
    validate_block_target(&ip)?;

    // Range already enforced by validation, so this cannot overflow.
    let blocked_until = payload
        .duration_seconds
        .map(|secs| chrono::Utc::now() + chrono::Duration::seconds(secs));

    let entry = sqlx::query_as::<_, BlockedIp>(
        r#"
        INSERT INTO blocked_ips (ip_address, reason, blocked_until)
        VALUES ($1, $2, $3)
        ON CONFLICT (ip_address) DO UPDATE
        SET reason = EXCLUDED.reason,
            blocked_until = EXCLUDED.blocked_until,
            blocked_at = CURRENT_TIMESTAMP
        RETURNING id, ip_address, reason, blocked_at, blocked_until
        "#,
    )
    .bind(ip)
    .bind(payload.reason.trim())
    .bind(blocked_until)
    .fetch_one(&state.pool)
    .await?;

    audit::record(
        &state.pool,
        Some(current_user.0.sub),
        "BLOCK_IP",
        &format!("{} ({})", ip, payload.reason.trim()),
        Some(client_ip.network()),
    )
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
    client_ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    require_admin(&current_user)?;

    let ip: IpNetwork =
        sqlx::query_scalar("DELETE FROM blocked_ips WHERE id = $1 RETURNING ip_address")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Blocklist entry {} not found", id)))?;

    audit::record(
        &state.pool,
        Some(current_user.0.sub),
        "UNBLOCK_IP",
        &ip.to_string(),
        Some(client_ip.network()),
    )
    .await;

    Ok(Json(ApiResponse::ok(format!("IP {} unblocked", ip))))
}

/// Deletes blocklist entries whose block period has ended. Returns the number removed.
pub async fn purge_expired_blocks(pool: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "DELETE FROM blocked_ips WHERE blocked_until IS NOT NULL AND blocked_until <= NOW()",
    )
    .execute(pool)
    .await?
    .rows_affected())
}
