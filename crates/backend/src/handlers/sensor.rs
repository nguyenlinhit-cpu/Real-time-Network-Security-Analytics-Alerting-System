use axum::{extract::State, http::HeaderMap, Json};
use common::models::{SensorHeartbeatDto, SensorStatusDto};
use common::ApiResponse;

use crate::{error::AppError, state::AppState};

/// Constant-time comparison so the sensor token cannot be guessed byte by byte via timing.
fn tokens_match(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// Sensors authenticate with the shared secret in `SENSOR_API_TOKEN`, sent as
/// `X-Sensor-Token`. Without a configured token the endpoint is disabled.
fn authorize_sensor(headers: &HeaderMap) -> Result<(), AppError> {
    let expected = std::env::var("SENSOR_API_TOKEN")
        .ok()
        .filter(|t| t.len() >= 16)
        .ok_or_else(|| {
            AppError::Forbidden(
                "Sensor heartbeat API is disabled (SENSOR_API_TOKEN not configured)".to_string(),
            )
        })?;
    let provided = headers
        .get("x-sensor-token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing X-Sensor-Token header".to_string()))?;
    if tokens_match(provided, &expected) {
        Ok(())
    } else {
        Err(AppError::Unauthorized("Invalid sensor token".to_string()))
    }
}

#[utoipa::path(
    post,
    path = "/api/sensor/heartbeat",
    request_body = SensorHeartbeatDto,
    params(
        ("X-Sensor-Token" = String, Header, description = "Shared sensor secret (SENSOR_API_TOKEN)")
    ),
    responses(
        (status = 200, description = "Sensor heartbeat recorded", body = ApiResponse<String>),
        (status = 401, description = "Missing or invalid sensor token", body = ApiResponse<()>)
    ),
    tag = "Sensor"
)]
pub async fn record_heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SensorHeartbeatDto>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    authorize_sensor(&headers)?;

    if payload.sensor_id.trim().is_empty() || payload.sensor_id.len() > 100 {
        return Err(AppError::BadRequest("Invalid sensor_id".to_string()));
    }

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
    .bind(payload.sensor_id.trim())
    .bind(&payload.sensor_version)
    .bind(&payload.interface_name)
    .bind(payload.packets_captured.max(0))
    .bind(payload.packets_dropped.max(0))
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
    tag = "Sensor",
    security(("bearer_auth" = []))
)]
pub async fn get_sensor_status(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<SensorStatusDto>>>, AppError> {
    // offline: no heartbeat for 60s; failed: sensor reported its capture source is down;
    // degraded: more than 1% of captured packets were dropped.
    let sensors = sqlx::query_as::<_, SensorStatusDto>(
        r#"
        SELECT
            sensor_id, sensor_version, interface_name,
            packets_captured, packets_dropped,
            CASE
                WHEN last_heartbeat < (CURRENT_TIMESTAMP - INTERVAL '60 seconds') THEN 'offline'
                WHEN status = 'failed' THEN 'failed'
                WHEN packets_dropped > 0
                     AND packets_dropped::FLOAT8 / GREATEST(packets_captured + packets_dropped, 1) > 0.01
                    THEN 'degraded'
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
