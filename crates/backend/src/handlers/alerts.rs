use axum::{
    extract::{Path, Query, State},
    Json,
};
use common::models::{Alert, AlertQueryFilter, AlertSeverity, AlertStatus, TrafficEvent, UpdateAlertDto};
use common::ApiResponse;
use ipnetwork::IpNetwork;
use uuid::Uuid;

use crate::{
    auth::{middleware::CurrentUser, rbac::require_analyst_or_admin},
    error::AppError,
    state::AppState,
};

#[utoipa::path(
    get,
    path = "/api/alerts",
    params(
        ("severity" = Option<AlertSeverity>, Query, description = "Filter by alert severity"),
        ("status" = Option<AlertStatus>, Query, description = "Filter by alert status"),
        ("src_ip" = Option<String>, Query, description = "Filter by source IP"),
        ("dst_ip" = Option<String>, Query, description = "Filter by destination IP"),
        ("search" = Option<String>, Query, description = "Search query for title or description"),
        ("limit" = Option<i64>, Query, description = "Maximum number of alerts (default 50)"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination (default 0)")
    ),
    responses(
        (status = 200, description = "List of security alerts", body = ApiResponse<Vec<Alert>>)
    ),
    tag = "Alerts",
    security(("bearer_auth" = []))
)]
pub async fn get_alerts(
    State(state): State<AppState>,
    Query(filter): Query<AlertQueryFilter>,
) -> Result<Json<ApiResponse<Vec<Alert>>>, AppError> {
    let limit = filter.limit.unwrap_or(50).clamp(1, 200);
    let offset = filter.offset.unwrap_or(0).max(0);
    let src_ip_parsed = filter.src_ip.as_deref().and_then(|s| s.parse::<IpNetwork>().ok());
    let dst_ip_parsed = filter.dst_ip.as_deref().and_then(|s| s.parse::<IpNetwork>().ok());
    let search_like = filter.search.as_ref().map(|s| format!("%{}%", s));

    let alerts = sqlx::query_as::<_, Alert>(
        r#"
        SELECT 
            id, rule_id, severity, title, description, src_ip, dst_ip,
            detected_at, status, acknowledged_by, resolved_at,
            mitre_tactic, mitre_technique
        FROM alerts
        WHERE ($1::alert_severity IS NULL OR severity = $1)
          AND ($2::alert_status IS NULL OR status = $2)
          AND ($3::INET IS NULL OR src_ip = $3)
          AND ($4::INET IS NULL OR dst_ip = $4)
          AND ($5::TEXT IS NULL OR title ILIKE $5 OR description ILIKE $5)
        ORDER BY detected_at DESC
        LIMIT $6 OFFSET $7
        "#,
    )
    .bind(filter.severity)
    .bind(filter.status)
    .bind(src_ip_parsed)
    .bind(dst_ip_parsed)
    .bind(search_like)
    .bind(limit)
    .bind(offset)
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
            detected_at, status, acknowledged_by, resolved_at,
            mitre_tactic, mitre_technique
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
    get,
    path = "/api/alerts/{id}/traffic",
    params(
        ("id" = Uuid, Path, description = "Alert UUID identifier")
    ),
    responses(
        (status = 200, description = "Traffic events associated with alert", body = ApiResponse<Vec<TrafficEvent>>),
        (status = 404, description = "Alert not found", body = ApiResponse<()>)
    ),
    tag = "Alerts",
    security(("bearer_auth" = []))
)]
pub async fn get_alert_traffic(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<TrafficEvent>>>, AppError> {
    let alert = sqlx::query_as::<_, Alert>(
        r#"
        SELECT 
            id, rule_id, severity, title, description, src_ip, dst_ip,
            detected_at, status, acknowledged_by, resolved_at,
            mitre_tactic, mitre_technique
        FROM alerts
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Alert with ID {} not found", id)))?;

    let from_time = alert.detected_at - chrono::Duration::minutes(5);
    let to_time = alert.detected_at + chrono::Duration::minutes(5);

    let traffic = sqlx::query_as::<_, TrafficEvent>(
        r#"
        SELECT 
            time, id, src_ip, dst_ip, src_port, dst_port,
            protocol, bytes_transferred, packet_count, flags, interface_name
        FROM traffic_events
        WHERE time >= $1 AND time <= $2
          AND ((src_ip = $3 AND dst_ip = $4) OR (src_ip = $4 AND dst_ip = $3))
        ORDER BY time DESC
        LIMIT 50
        "#,
    )
    .bind(from_time)
    .bind(to_time)
    .bind(alert.src_ip)
    .bind(alert.dst_ip)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(ApiResponse::ok(traffic)))
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
        r#"
        SELECT 
            id, rule_id, severity, title, description, src_ip, dst_ip,
            detected_at, status, acknowledged_by, resolved_at,
            mitre_tactic, mitre_technique
        FROM alerts
        WHERE id = $1
        "#
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
            detected_at, status, acknowledged_by, resolved_at,
            mitre_tactic, mitre_technique
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
