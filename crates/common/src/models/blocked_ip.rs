use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct BlockedIp {
    pub id: Uuid,
    #[cfg_attr(feature = "utoipa", schema(value_type = String, example = "10.0.0.99/32"))]
    pub ip_address: IpNetwork,
    pub reason: String,
    pub blocked_at: DateTime<Utc>,
    pub blocked_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateBlockedIpDto {
    pub ip_address: String,
    #[validate(length(min = 3, max = 500))]
    pub reason: String,
    pub duration_seconds: Option<i64>,
}
