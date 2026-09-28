use axum::{
    extract::{Path, State},
    Json,
};
use common::models::{Device, TrafficEvent};
use common::ApiResponse;
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

#[utoipa::path(
    get,
    path = "/api/devices",
    responses(
        (status = 200, description = "List of discovered network devices", body = ApiResponse<Vec<Device>>)
    ),
    tag = "Devices",
    security(("bearer_auth" = []))
)]
pub async fn get_devices(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Device>>>, AppError> {
    let devices = sqlx::query_as::<_, Device>(
        r#"
        SELECT 
            id, ip_address, mac_address::TEXT as mac_address, hostname,
            device_type, first_seen, last_seen, is_trusted
        FROM devices
        ORDER BY last_seen DESC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(ApiResponse::ok(devices)))
}

#[utoipa::path(
    get,
    path = "/api/devices/{id}/history",
    params(
        ("id" = Uuid, Path, description = "Device UUID identifier")
    ),
    responses(
        (status = 200, description = "Recent traffic events associated with the device", body = ApiResponse<Vec<TrafficEvent>>)
    ),
    tag = "Devices",
    security(("bearer_auth" = []))
)]
pub async fn get_device_history(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<TrafficEvent>>>, AppError> {
    let device = sqlx::query_as::<_, Device>(
        "SELECT id, ip_address, mac_address::TEXT as mac_address, hostname, device_type, first_seen, last_seen, is_trusted FROM devices WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Device {} not found", id)))?;

    let events = sqlx::query_as::<_, TrafficEvent>(
        r#"
        SELECT 
            time, id, src_ip, dst_ip, src_port, dst_port,
            protocol, bytes_transferred, packet_count, flags, interface_name
        FROM traffic_events
        WHERE src_ip = $1 OR dst_ip = $1
        ORDER BY time DESC
        LIMIT 50
        "#,
    )
    .bind(device.ip_address)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(ApiResponse::ok(events)))
}
