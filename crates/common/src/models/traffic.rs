use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TrafficEvent {
    pub time: DateTime<Utc>,
    pub id: Uuid,
    #[cfg_attr(feature = "utoipa", schema(value_type = String, example = "192.168.1.100/32"))]
    pub src_ip: IpNetwork,
    #[cfg_attr(feature = "utoipa", schema(value_type = String, example = "192.168.1.50/32"))]
    pub dst_ip: IpNetwork,
    pub src_port: i32,
    pub dst_port: i32,
    pub protocol: String,
    pub bytes_transferred: i64,
    pub packet_count: i32,
    pub flags: String,
    pub interface_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TrafficSummaryDto {
    pub total_packets: i64,
    pub total_bytes: i64,
    pub total_alerts: i64,
    #[serde(default)]
    pub critical_alerts: i64,
    pub top_src_ips: Vec<TopEntityDto>,
    pub top_dst_ports: Vec<TopEntityDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TopEntityDto {
    pub key: String,
    pub count: i64,
    pub bytes: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TrafficQueryFilter {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub protocol: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Batched live-traffic update pushed over `/ws/traffic`.
/// `events` holds only a small sample; the totals cover every event in the batch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct TrafficBatchDto {
    pub events: Vec<TrafficEvent>,
    pub total_bytes: i64,
    pub total_packets: i64,
}
