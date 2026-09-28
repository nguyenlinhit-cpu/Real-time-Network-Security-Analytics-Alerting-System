use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(
    feature = "sqlx",
    sqlx(type_name = "alert_severity", rename_all = "lowercase")
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum AlertSeverity {
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(
    feature = "sqlx",
    sqlx(type_name = "alert_status", rename_all = "lowercase")
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum AlertStatus {
    #[default]
    Open,
    Acknowledged,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Alert {
    pub id: Uuid,
    pub rule_id: Option<Uuid>,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    #[cfg_attr(feature = "utoipa", schema(value_type = String, example = "10.0.0.99/32"))]
    pub src_ip: IpNetwork,
    #[cfg_attr(feature = "utoipa", schema(value_type = String, example = "192.168.1.50/32"))]
    pub dst_ip: IpNetwork,
    pub detected_at: DateTime<Utc>,
    pub status: AlertStatus,
    pub acknowledged_by: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateAlertDto {
    pub rule_id: Option<Uuid>,
    pub severity: AlertSeverity,
    #[validate(length(min = 3, max = 255))]
    pub title: String,
    pub description: String,
    pub src_ip: String,
    pub dst_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct UpdateAlertDto {
    pub status: AlertStatus,
}
