use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct SensorHeartbeatDto {
    pub sensor_id: String,
    pub sensor_version: String,
    pub interface_name: String,
    pub packets_captured: i64,
    pub packets_dropped: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct SensorStatusDto {
    pub sensor_id: String,
    pub sensor_version: String,
    pub interface_name: String,
    pub packets_captured: i64,
    pub packets_dropped: i64,
    pub status: String,
    pub last_heartbeat: DateTime<Utc>,
}
