use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::state::AppState;

static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
static HTTP_REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn init_metrics() {
    START_TIME.get_or_init(Instant::now);
}

pub fn increment_http_requests() {
    HTTP_REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed);
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "Prometheus exposition format metrics", body = String)
    ),
    tag = "System"
)]
pub async fn metrics_handler(State(state): State<AppState>) -> Response {
    let start = START_TIME.get_or_init(Instant::now);
    let uptime_secs = start.elapsed().as_secs();
    let requests_total = HTTP_REQUESTS_TOTAL.load(Ordering::Relaxed);

    let active_rate_limits = state.rate_limiter.len();
    let active_failed_logins = state.failed_logins.len();

    // Query high-level aggregates from database with quick count queries
    let total_alerts: i64 = sqlx::query_scalar("SELECT count(*) FROM alerts")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);

    let critical_alerts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM alerts WHERE severity = 'critical'")
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

    let blocked_ips: i64 = sqlx::query_scalar("SELECT count(*) FROM blocked_ips")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);

    let discovered_devices: i64 = sqlx::query_scalar("SELECT count(*) FROM devices")
        .fetch_one(&state.pool)
        .await
        .unwrap_or(0);

    let output = format!(
        "# HELP secnet_uptime_seconds Total runtime of SecNet server in seconds.\n\
         # TYPE secnet_uptime_seconds counter\n\
         secnet_uptime_seconds {}\n\n\
         # HELP secnet_http_requests_total Total number of processed HTTP requests.\n\
         # TYPE secnet_http_requests_total counter\n\
         secnet_http_requests_total {}\n\n\
         # HELP secnet_active_rate_limit_entries Currently active rate limit buckets.\n\
         # TYPE secnet_active_rate_limit_entries gauge\n\
         secnet_active_rate_limit_entries {}\n\n\
         # HELP secnet_failed_login_records Tracked accounts with recent login failures.\n\
         # TYPE secnet_failed_login_records gauge\n\
         secnet_failed_login_records {}\n\n\
         # HELP secnet_alerts_total Total security incident alerts logged.\n\
         # TYPE secnet_alerts_total counter\n\
         secnet_alerts_total {}\n\n\
         # HELP secnet_critical_alerts_total Total critical incident alerts.\n\
         # TYPE secnet_critical_alerts_total counter\n\
         secnet_critical_alerts_total {}\n\n\
         # HELP secnet_blocked_ips_total Active blocked malicious IPs.\n\
         # TYPE secnet_blocked_ips_total gauge\n\
         secnet_blocked_ips_total {}\n\n\
         # HELP secnet_discovered_devices_total Total network devices inventoried.\n\
         # TYPE secnet_discovered_devices_total gauge\n\
         secnet_discovered_devices_total {}\n",
        uptime_secs,
        requests_total,
        active_rate_limits,
        active_failed_logins,
        total_alerts,
        critical_alerts,
        blocked_ips,
        discovered_devices
    );

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        output,
    )
        .into_response()
}
