use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub target: String,
    pub timestamp: DateTime<Utc>,
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>, example = "192.168.1.105/32"))]
    pub ip_address: Option<IpNetwork>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateAuditLogDto {
    pub user_id: Option<Uuid>,
    pub action: String,
    pub target: String,
    pub ip_address: Option<String>,
}
