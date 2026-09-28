use axum::{
    middleware,
    routing::{delete, get, patch, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    auth::middleware::auth_middleware,
    handlers::*,
    middleware::{correlation_id_middleware, rate_limit_middleware, security_headers_middleware},
    state::AppState,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        metrics::metrics_handler,
        auth::register,
        auth::login,
        auth::refresh_token,
        auth::logout,
        dashboard::get_dashboard_summary,
        traffic::get_traffic,
        alerts::get_alerts,
        alerts::get_alert_by_id,
        alerts::update_alert_status,
        rules::get_rules,
        rules::get_rule_by_id,
        rules::create_rule,
        rules::update_rule,
        rules::delete_rule,
        devices::get_devices,
        devices::get_device_history,
        blocklist::get_blocklist,
        blocklist::add_to_blocklist,
        blocklist::remove_from_blocklist,
        notifications::get_channels,
        notifications::create_channel,
        notifications::update_channel,
        notifications::delete_channel,
        notifications::test_channel,
    ),
    components(
        schemas(
            common::ApiResponse<common::models::UserPublicDto>,
            common::ApiResponse<common::models::AuthResponseDto>,
            common::ApiResponse<common::models::TrafficSummaryDto>,
            common::ApiResponse<Vec<common::models::TrafficEvent>>,
            common::ApiResponse<Vec<common::models::Alert>>,
            common::ApiResponse<common::models::Alert>,
            common::ApiResponse<Vec<common::models::DetectionRule>>,
            common::ApiResponse<common::models::DetectionRule>,
            common::ApiResponse<Vec<common::models::Device>>,
            common::ApiResponse<Vec<common::models::BlockedIp>>,
            common::ApiResponse<common::models::BlockedIp>,
            common::ApiResponse<Vec<common::models::NotificationChannel>>,
            common::ApiResponse<common::models::NotificationChannel>,
            common::ApiResponse<String>,
            common::models::CreateUserDto,
            common::models::LoginDto,
            auth::RefreshTokenPayload,
            common::models::UpdateAlertDto,
            common::models::CreateRuleDto,
            common::models::UpdateRuleDto,
            common::models::CreateBlockedIpDto,
            common::models::CreateNotificationChannelDto,
            common::models::UpdateNotificationChannelDto,
        )
    ),
    tags(
        (name = "Auth", description = "Authentication & Token Management"),
        (name = "Dashboard", description = "Summary & Incident Metrics"),
        (name = "Traffic", description = "Real-time & Historical Network Traffic"),
        (name = "Alerts", description = "Security Incidents Management"),
        (name = "Rules", description = "Detection Rule Configurations"),
        (name = "Devices", description = "Discovered Network Nodes & Inventory"),
        (name = "Blocklist", description = "Active IP Blacklist & Threat Mitigation"),
        (name = "Notifications", description = "Notification Channel Settings & Dispatch")
    )
)]
pub struct ApiDoc;

pub fn create_router(state: AppState) -> Router {
    // 1. Public authentication routes
    let auth_routes = Router::new()
        .route("/api/auth/register", post(auth::register))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/refresh", post(auth::refresh_token));

    // 2. Protected REST API routes
    let protected_routes = Router::new()
        .route(
            "/api/dashboard/summary",
            get(dashboard::get_dashboard_summary),
        )
        .route("/api/traffic", get(traffic::get_traffic))
        .route("/api/alerts", get(alerts::get_alerts))
        .route(
            "/api/alerts/:id",
            get(alerts::get_alert_by_id).patch(alerts::update_alert_status),
        )
        .route(
            "/api/alerts/:id/traffic",
            get(alerts::get_alert_traffic),
        )
        .route("/api/audit-logs", get(audit_logs::get_audit_logs))
        .route("/api/sensor/status", get(sensor::get_sensor_status))
        .route("/api/rules", get(rules::get_rules).post(rules::create_rule))
        .route(
            "/api/rules/:id",
            get(rules::get_rule_by_id)
                .patch(rules::update_rule)
                .delete(rules::delete_rule),
        )
        .route("/api/devices", get(devices::get_devices))
        .route("/api/devices/:id/history", get(devices::get_device_history))
        .route(
            "/api/blocklist",
            get(blocklist::get_blocklist).post(blocklist::add_to_blocklist),
        )
        .route(
            "/api/blocklist/:id",
            delete(blocklist::remove_from_blocklist),
        )
        .route("/api/reports/export", get(reports::export_reports))
        .route(
            "/api/notifications/channels",
            get(notifications::get_channels).post(notifications::create_channel),
        )
        .route(
            "/api/notifications/channels/:id",
            patch(notifications::update_channel).delete(notifications::delete_channel),
        )
        .route(
            "/api/notifications/test/:id",
            post(notifications::test_channel),
        )
        .route("/api/auth/logout", post(auth::logout))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    // 3. WebSocket routes (real-time push)
    let ws_routes = Router::new()
        .route("/ws/alerts", get(ws::ws_alerts_handler))
        .route("/ws/traffic", get(ws::ws_traffic_handler));

    // 4. System & Observability routes
    let system_routes = Router::new()
        .route("/metrics", get(metrics::metrics_handler))
        .route(
            "/health",
            get(|| async {
                axum::Json(serde_json::json!({"status": "ok", "service": "secnet-backend"}))
            }),
        )
        .route(
            "/api/health",
            get(|| async {
                axum::Json(serde_json::json!({"status": "ok", "service": "secnet-backend"}))
            }),
        );

    // 5. Configurable CORS whitelist (Mục 13)
    let cors_env =
        std::env::var("CORS_ALLOWED_ORIGINS").or_else(|_| std::env::var("CORS_ALLOWED_ORIGIN"));
    let cors = if let Ok(origins_str) = cors_env {
        let origins: Vec<axum::http::HeaderValue> = origins_str
            .split(',')
            .filter_map(|s| s.trim().parse::<axum::http::HeaderValue>().ok())
            .collect();
        if origins.is_empty() {
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
        } else {
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods(Any)
                .allow_headers(Any)
        }
    } else {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    };

    Router::new()
        .merge(auth_routes)
        .merge(protected_routes)
        .merge(ws_routes)
        .merge(system_routes)
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn(correlation_id_middleware))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(cors)
        .with_state(state)
}
