use ipnetwork::IpNetwork;
use sqlx::PgPool;
use uuid::Uuid;

/// Best-effort audit trail write. Audit failures are logged but never fail the caller's request.
pub async fn record(
    pool: &PgPool,
    user_id: Option<Uuid>,
    action: &str,
    target: &str,
    ip: Option<IpNetwork>,
) {
    let res = sqlx::query(
        "INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(action)
    .bind(target)
    .bind(ip)
    .execute(pool)
    .await;

    if let Err(e) = res {
        tracing::warn!("Failed to write audit log '{}': {}", action, e);
    }
}
