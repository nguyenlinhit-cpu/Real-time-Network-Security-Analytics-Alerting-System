use axum::{extract::State, Json};
use common::ApiResponse;
use serde::{Deserialize, Serialize};

use crate::{error::AppError, state::AppState};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct SensorHeartbeatDto {
    pub sensor_id: String,
    pub sensor_version: String,
    pub interface_name: String,
    pub packets_captured: i64,
    pub packets_dropped: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct SensorStatusDto {
    pub sensor_id: String,
    pub sensor_version: String,
    pub interface_name: String,
    pub packets_captured: i64,
    pub packets_dropped: i64,
    pub status: String,
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
}

#[utoipa::path(
    post,
    path = "/api/sensor/heartbeat",
    request_body = SensorHeartbeatDto,
    responses(
        (status = 200, description = "Sensor heartbeat recorded", body = ApiResponse<String>)
    ),
    tag = "Sensor"
)]
pub async fn record_heartbeat(
    State(state): State<AppState>,
    Json(payload): Json<SensorHeartbeatDto>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    sqlx::query(
        r#"
        INSERT INTO sensor_heartbeats (sensor_id, sensor_version, interface_name, packets_captured, packets_dropped, status, last_heartbeat)
        VALUES ($1, $2, $3, $4, $5, 'healthy', CURRENT_TIMESTAMP)
        ON CONFLICT (sensor_id) DO UPDATE SET
            sensor_version = EXCLUDED.sensor_version,
            interface_name = EXCLUDED.interface_name,
            packets_captured = EXCLUDED.packets_captured,
            packets_dropped = EXCLUDED.packets_dropped,
            status = 'healthy',
            last_heartbeat = CURRENT_TIMESTAMP
        "#,
    )
    .bind(&payload.sensor_id)
    .bind(&payload.sensor_version)
    .bind(&payload.interface_name)
    .bind(payload.packets_captured)
    .bind(payload.packets_dropped)
    .execute(&state.pool)
    .await?;

    Ok(Json(ApiResponse::ok("Heartbeat recorded".to_string())))
}

#[utoipa::path(
    get,
    path = "/api/sensor/status",
    responses(
        (status = 200, description = "Sensor operational status list", body = ApiResponse<Vec<SensorStatusDto>>)
    ),
    tag = "Sensor"
)]
pub async fn get_sensor_status(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<SensorStatusDto>>>, AppError> {
    // If a sensor hasn't reported in over 60s, mark as offline
    let sensors = sqlx::query_as::<_, SensorStatusDto>(
        r#"
        SELECT 
            sensor_id, sensor_version, interface_name,
            packets_captured, packets_dropped,
            CASE 
                WHEN last_heartbeat < (CURRENT_TIMESTAMP - INTERVAL '60 seconds') THEN 'offline'
                WHEN packets_dropped > 1000 THEN 'degraded'
                ELSE 'healthy'
            END as status,
            last_heartbeat
        FROM sensor_heartbeats
        ORDER BY sensor_id ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(ApiResponse::ok(sensors)))
}
