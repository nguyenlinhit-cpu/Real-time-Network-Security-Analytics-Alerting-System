use axum::{extract::State, Json};
use common::models::{TopEntityDto, TrafficSummaryDto};
use common::ApiResponse;

use crate::{error::AppError, state::AppState};

#[utoipa::path(
    get,
    path = "/api/dashboard/summary",
    responses(
        (status = 200, description = "Aggregated security dashboard summary", body = ApiResponse<TrafficSummaryDto>)
    ),
    tag = "Dashboard",
    security(("bearer_auth" = []))
)]
pub async fn get_dashboard_summary(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<TrafficSummaryDto>>, AppError> {
    // 1. Total packets and bytes from traffic_events
    let traffic_stats = sqlx::query!(
        r#"
        SELECT 
            COALESCE(SUM(packet_count), 0)::BIGINT as total_packets,
            COALESCE(SUM(bytes_transferred), 0)::BIGINT as total_bytes
        FROM traffic_events
        "#
    )
    .fetch_one(&state.pool)
    .await?;

    // 2. Total active/unresolved alerts count (Mục 34)
    let total_alerts: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM alerts WHERE status != 'resolved'")
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0);

    // 3. Top talkers (Source IPs by packet count)
    let top_ips = sqlx::query!(
        r#"
        SELECT 
            host(src_ip)::TEXT as src_ip_str,
            COUNT(*)::BIGINT as pkt_count,
            COALESCE(SUM(bytes_transferred), 0)::BIGINT as total_bytes
        FROM traffic_events
        GROUP BY src_ip
        ORDER BY pkt_count DESC
        LIMIT 5
        "#
    )
    .fetch_all(&state.pool)
    .await?;

    let top_src_ips = top_ips
        .into_iter()
        .map(|row| TopEntityDto {
            key: row.src_ip_str.unwrap_or_else(|| "unknown".to_string()),
            count: row.pkt_count.unwrap_or(0),
            bytes: row.total_bytes.unwrap_or(0),
        })
        .collect();

    // 4. Top destination ports
    let top_ports_data = sqlx::query!(
        r#"
        SELECT 
            dst_port::TEXT as port_str,
            COUNT(*)::BIGINT as port_count,
            COALESCE(SUM(bytes_transferred), 0)::BIGINT as total_bytes
        FROM traffic_events
        GROUP BY dst_port
        ORDER BY port_count DESC
        LIMIT 5
        "#
    )
    .fetch_all(&state.pool)
    .await?;

    let top_dst_ports = top_ports_data
        .into_iter()
        .map(|row| TopEntityDto {
            key: row.port_str.unwrap_or_else(|| "0".to_string()),
            count: row.port_count.unwrap_or(0),
            bytes: row.total_bytes.unwrap_or(0),
        })
        .collect();

    let summary = TrafficSummaryDto {
        total_packets: traffic_stats.total_packets.unwrap_or(0),
        total_bytes: traffic_stats.total_bytes.unwrap_or(0),
        total_alerts,
        top_src_ips,
        top_dst_ports,
    };

    Ok(Json(ApiResponse::ok(summary)))
}
