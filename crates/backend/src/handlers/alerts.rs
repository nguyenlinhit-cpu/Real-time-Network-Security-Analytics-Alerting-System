use axum::{
    extract::{Path, Query, State},
    Json,
};
use common::models::{Alert, AlertQueryFilter, AlertStatus, TrafficEvent, UpdateAlertDto, UserRole};
use common::ApiResponse;
use uuid::Uuid;

use crate::{
    audit,
    auth::{middleware::CurrentUser, rbac::require_analyst_or_admin},
    error::AppError,
    handlers::filters::{like_pattern, parse_ip_filter},
    middleware::ClientIp,
    state::AppState,
};

const ALERT_COLUMNS: &str = "id, rule_id, severity, title, description, src_ip, dst_ip, \
     detected_at, status, acknowledged_by, resolved_at, mitre_tactic, mitre_technique";

async fn fetch_alert(state: &AppState, id: Uuid) -> Result<Alert, AppError> {
    sqlx::query_as::<_, Alert>(&format!("SELECT {} FROM alerts WHERE id = $1", ALERT_COLUMNS))
        .bind(id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Alert with ID {} not found", id)))
}

/// Allowed incident lifecycle transitions. `Resolved -> Open` is a deliberate re-open.
fn is_valid_transition(from: AlertStatus, to: AlertStatus) -> bool {
    use AlertStatus::*;
    matches!(
        (from, to),
        (Open, Acknowledged)
            | (Open, Resolved)
            | (Acknowledged, Resolved)
            | (Acknowledged, Open)
            | (Resolved, Open)
    )
}

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
        (status = 200, description = "List of security alerts", body = ApiResponse<Vec<Alert>>),
        (status = 400, description = "Invalid filter", body = ApiResponse<()>)
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
    let src_ip_parsed = parse_ip_filter("src_ip", filter.src_ip.as_deref())?;
    let dst_ip_parsed = parse_ip_filter("dst_ip", filter.dst_ip.as_deref())?;
    let search_like = like_pattern(filter.search.as_deref());

    let alerts = sqlx::query_as::<_, Alert>(&format!(
        r#"
        SELECT {}
        FROM alerts
        WHERE ($1::alert_severity IS NULL OR severity = $1)
          AND ($2::alert_status IS NULL OR status = $2)
          AND ($3::INET IS NULL OR src_ip = $3)
          AND ($4::INET IS NULL OR dst_ip = $4)
          AND ($5::TEXT IS NULL OR title ILIKE $5 OR description ILIKE $5
               OR host(src_ip) ILIKE $5 OR host(dst_ip) ILIKE $5)
        ORDER BY detected_at DESC
        LIMIT $6 OFFSET $7
        "#,
        ALERT_COLUMNS
    ))
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
    Ok(Json(ApiResponse::ok(fetch_alert(&state, id).await?)))
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
    let alert = fetch_alert(&state, id).await?;

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
        (status = 400, description = "Invalid status transition", body = ApiResponse<()>),
        (status = 403, description = "Insufficient role permissions", body = ApiResponse<()>)
    ),
    tag = "Alerts",
    security(("bearer_auth" = []))
)]
pub async fn update_alert_status(
    State(state): State<AppState>,
    current_user: CurrentUser,
    client_ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateAlertDto>,
) -> Result<Json<ApiResponse<Alert>>, AppError> {
    require_analyst_or_admin(&current_user)?;

    let existing = fetch_alert(&state, id).await?;

    // An incident owned by one analyst can only be changed by that analyst or an Admin.
    if let Some(owner) = existing.acknowledged_by {
        if owner != current_user.0.sub && current_user.0.role != UserRole::Admin {
            return Err(AppError::Forbidden(
                "This incident is assigned to another analyst. Only an Administrator can override or resolve it.".to_string(),
            ));
        }
    }

    if existing.status == payload.status {
        return Ok(Json(ApiResponse::ok(existing)));
    }
    if !is_valid_transition(existing.status, payload.status) {
        return Err(AppError::BadRequest(format!(
            "Cannot change incident status from {:?} to {:?}",
            existing.status, payload.status
        )));
    }

    // Re-opened incidents are unassigned again; acknowledged/resolved ones belong to the actor.
    let (owner, resolved_at) = match payload.status {
        AlertStatus::Open => (None, None),
        AlertStatus::Acknowledged => (Some(current_user.0.sub), None),
        AlertStatus::Resolved => (Some(current_user.0.sub), Some(chrono::Utc::now())),
    };

    let updated_alert = sqlx::query_as::<_, Alert>(&format!(
        r#"
        UPDATE alerts
        SET status = $1, acknowledged_by = $2, resolved_at = $3
        WHERE id = $4
        RETURNING {}
        "#,
        ALERT_COLUMNS
    ))
    .bind(payload.status)
    .bind(owner)
    .bind(resolved_at)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Alert with ID {} not found", id)))?;

    audit::record(
        &state.pool,
        Some(current_user.0.sub),
        &format!("UPDATE_ALERT_STATUS:{:?}", payload.status),
        &id.to_string(),
        Some(client_ip.network()),
    )
    .await;

    Ok(Json(ApiResponse::ok(updated_alert)))
}
