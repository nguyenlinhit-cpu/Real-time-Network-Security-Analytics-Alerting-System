use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use super::alert::AlertSeverity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "sqlx", derive(sqlx::Type))]
#[cfg_attr(
    feature = "sqlx",
    sqlx(type_name = "channel_type", rename_all = "lowercase")
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum ChannelType {
    #[default]
    Email,
    Webhook,
    Telegram,
    Slack,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct NotificationChannel {
    pub id: Uuid,
    pub name: String,
    pub r#type: ChannelType,
    #[cfg_attr(feature = "sqlx", sqlx(json))]
    pub config_json: serde_json::Value,
    pub min_severity: AlertSeverity,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateNotificationChannelDto {
    #[validate(length(min = 2, max = 100))]
    pub name: String,
    pub r#type: ChannelType,
    pub config_json: serde_json::Value,
    pub min_severity: AlertSeverity,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct UpdateNotificationChannelDto {
    #[validate(length(min = 2, max = 100))]
    pub name: Option<String>,
    pub r#type: Option<ChannelType>,
    pub config_json: Option<serde_json::Value>,
    pub min_severity: Option<AlertSeverity>,
    pub is_enabled: Option<bool>,
}
