use axum::{extract::State, Json};
use common::models::{TopEntityDto, TrafficSummaryDto};
use common::ApiResponse;

use crate::{error::AppError, state::AppState};

#[utoipa::path(
    get,
    path = "/api/dashboard/summary",
    responses(
        (status = 200, description = "Aggregated security dashboard summary (traffic over the last 24 hours)", body = ApiResponse<TrafficSummaryDto>)
    ),
    tag = "Dashboard",
    security(("bearer_auth" = []))
)]
pub async fn get_dashboard_summary(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<TrafficSummaryDto>>, AppError> {
    // Traffic figures are bounded to the last 24h so the query only touches recent
    // hypertable chunks instead of scanning the full retention period.
    let (total_packets, total_bytes): (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COALESCE(SUM(packet_count), 0)::BIGINT,
            COALESCE(SUM(bytes_transferred), 0)::BIGINT
        FROM traffic_events
        WHERE time > NOW() - INTERVAL '24 hours'
        "#,
    )
    .fetch_one(&state.pool)
    .await?;

    let (total_alerts, critical_alerts): (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*)::BIGINT,
            COUNT(*) FILTER (WHERE severity = 'critical')::BIGINT
        FROM alerts
        WHERE status != 'resolved'
        "#,
    )
    .fetch_one(&state.pool)
    .await?;

    let top_src_ips = sqlx::query_as::<_, (String, i64, i64)>(
        r#"
        SELECT
            host(src_ip),
            COALESCE(SUM(packet_count), 0)::BIGINT AS packets,
            COALESCE(SUM(bytes_transferred), 0)::BIGINT
        FROM traffic_events
        WHERE time > NOW() - INTERVAL '24 hours'
        GROUP BY src_ip
        ORDER BY packets DESC
        LIMIT 5
        "#,
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|(key, count, bytes)| TopEntityDto { key, count, bytes })
    .collect();

    let top_dst_ports = sqlx::query_as::<_, (i32, i64, i64)>(
        r#"
        SELECT
            dst_port,
            COALESCE(SUM(packet_count), 0)::BIGINT AS packets,
            COALESCE(SUM(bytes_transferred), 0)::BIGINT
        FROM traffic_events
        WHERE time > NOW() - INTERVAL '24 hours'
        GROUP BY dst_port
        ORDER BY packets DESC
        LIMIT 5
        "#,
    )
    .fetch_all(&state.pool)
    .await?
    .into_iter()
    .map(|(port, count, bytes)| TopEntityDto {
        key: port.to_string(),
        count,
        bytes,
    })
    .collect();

    Ok(Json(ApiResponse::ok(TrafficSummaryDto {
        total_packets,
        total_bytes,
        total_alerts,
        critical_alerts,
        top_src_ips,
        top_dst_ports,
    })))
}
