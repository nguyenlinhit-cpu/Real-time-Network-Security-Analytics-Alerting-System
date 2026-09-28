use axum::{
    extract::{Query, State},
    Json,
};
use common::models::{TrafficEvent, TrafficQueryFilter};
use common::ApiResponse;

use crate::{error::AppError, handlers::filters::parse_ip_filter, state::AppState};

#[utoipa::path(
    get,
    path = "/api/traffic",
    params(
        ("from" = Option<chrono::DateTime<chrono::Utc>>, Query, description = "Start time range filter"),
        ("to" = Option<chrono::DateTime<chrono::Utc>>, Query, description = "End time range filter"),
        ("src_ip" = Option<String>, Query, description = "Source IP address filter"),
        ("dst_ip" = Option<String>, Query, description = "Destination IP address filter"),
        ("protocol" = Option<String>, Query, description = "Protocol (TCP/UDP/ICMP) filter"),
        ("limit" = Option<i64>, Query, description = "Number of events to retrieve (default 50)"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination")
    ),
    responses(
        (status = 200, description = "List of traffic events", body = ApiResponse<Vec<TrafficEvent>>)
    ),
    tag = "Traffic",
    security(("bearer_auth" = []))
)]
pub async fn get_traffic(
    State(state): State<AppState>,
    Query(filter): Query<TrafficQueryFilter>,
) -> Result<Json<ApiResponse<Vec<TrafficEvent>>>, AppError> {
    let limit = filter.limit.unwrap_or(50).clamp(1, 500);
    let offset = filter.offset.unwrap_or(0).max(0);
    let src_ip_parsed = parse_ip_filter("src_ip", filter.src_ip.as_deref())?;
    let dst_ip_parsed = parse_ip_filter("dst_ip", filter.dst_ip.as_deref())?;
    let protocol = filter
        .protocol
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_uppercase);

    let events = sqlx::query_as::<_, TrafficEvent>(
        r#"
        SELECT 
            time, id, src_ip, dst_ip, src_port, dst_port,
            protocol, bytes_transferred, packet_count, flags, interface_name
        FROM traffic_events
        WHERE ($1::TIMESTAMPTZ IS NULL OR time >= $1)
          AND ($2::TIMESTAMPTZ IS NULL OR time <= $2)
          AND ($3::INET IS NULL OR src_ip = $3)
          AND ($4::INET IS NULL OR dst_ip = $4)
          AND ($5::TEXT IS NULL OR upper(protocol) = $5)
        ORDER BY time DESC
        LIMIT $6 OFFSET $7
        "#,
    )
    .bind(filter.from)
    .bind(filter.to)
    .bind(src_ip_parsed)
    .bind(dst_ip_parsed)
    .bind(protocol)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(ApiResponse::ok(events)))
}
