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
    sqlx(type_name = "rule_type", rename_all = "lowercase")
)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub enum RuleType {
    #[default]
    Threshold,
    Pattern,
    Anomaly,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "sqlx", derive(sqlx::FromRow))]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct DetectionRule {
    pub id: Uuid,
    pub name: String,
    pub rule_type: RuleType,
    #[cfg_attr(feature = "sqlx", sqlx(json))]
    pub condition_json: serde_json::Value,
    pub severity: AlertSeverity,
    pub is_enabled: bool,
    pub threshold_value: f64,
    pub time_window_seconds: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CreateRuleDto {
    #[validate(length(min = 3, max = 100))]
    pub name: String,
    pub rule_type: RuleType,
    pub condition_json: serde_json::Value,
    pub severity: AlertSeverity,
    pub is_enabled: Option<bool>,
    pub threshold_value: f64,
    pub time_window_seconds: i32,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct UpdateRuleDto {
    pub name: Option<String>,
    pub rule_type: Option<RuleType>,
    pub condition_json: Option<serde_json::Value>,
    pub severity: Option<AlertSeverity>,
    pub is_enabled: Option<bool>,
    pub threshold_value: Option<f64>,
    pub time_window_seconds: Option<i32>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
}
