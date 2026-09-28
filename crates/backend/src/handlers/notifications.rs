use axum::{
    extract::{Path, State},
    Json,
};
use common::models::{
    Alert, AlertSeverity, AlertStatus, ChannelType, CreateNotificationChannelDto,
    NotificationChannel, UpdateNotificationChannelDto, UserRole,
};
use common::ApiResponse;
use uuid::Uuid;
use validator::Validate;

use crate::{
    alerting::validate_webhook_url,
    audit,
    auth::{middleware::CurrentUser, rbac::require_admin},
    error::AppError,
    middleware::ClientIp,
    state::AppState,
};

const MASK: &str = "********";

fn is_secret_key(key: &str) -> bool {
    let k = key.to_lowercase();
    ["token", "password", "secret", "key", "auth", "credential", "header", "cookie"]
        .iter()
        .any(|s| k.contains(s))
}

/// Keeps only `scheme://host` of a URL: webhook URLs (Slack, SIEM…) often embed secrets in
/// their path or query string.
fn mask_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(u) => format!("{}://{}/{}", u.scheme(), u.host_str().unwrap_or(""), MASK),
        Err(_) => MASK.to_string(),
    }
}

/// Recursively masks secrets in a channel config for non-admin viewers (Mục 11).
pub fn mask_sensitive_config(config: &mut serde_json::Value) {
    match config {
        serde_json::Value::Object(obj) => {
            for (k, v) in obj.iter_mut() {
                if is_secret_key(k) {
                    *v = serde_json::json!(MASK);
                } else if k.to_lowercase().contains("url") {
                    if let Some(s) = v.as_str() {
                        *v = serde_json::json!(mask_url(s));
                    } else {
                        *v = serde_json::json!(MASK);
                    }
                } else {
                    mask_sensitive_config(v);
                }
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(mask_sensitive_config),
        _ => {}
    }
}

/// Validates the channel-specific config: required keys are present and webhook targets pass
/// the SSRF checks (Mục 21).
async fn validate_channel_config(
    channel_type: ChannelType,
    config: &serde_json::Value,
) -> Result<(), AppError> {
    let require = |key: &str| -> Result<&str, AppError> {
        config
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::BadRequest(format!("Channel config requires '{}'", key)))
    };

    match channel_type {
        ChannelType::Webhook => {
            validate_webhook_url(require("endpoint_url")?, true).await?;
        }
        ChannelType::Slack => {
            validate_webhook_url(require("webhook_url")?, true).await?;
        }
        ChannelType::Telegram => {
            require("bot_token")?;
            require("chat_id")?;
        }
        ChannelType::Email => {
            require("smtp_host")?;
            require("to_email")?;
        }
    }
    Ok(())
}

const CHANNEL_COLUMNS: &str =
    "id, name, type, config_json, min_severity, is_enabled, created_at, updated_at";

#[utoipa::path(
    get,
    path = "/api/notifications/channels",
    responses(
        (status = 200, description = "List notification channels", body = ApiResponse<Vec<NotificationChannel>>)
    ),
    tag = "Notifications",
    security(("bearer_auth" = []))
)]
pub async fn get_channels(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<ApiResponse<Vec<NotificationChannel>>>, AppError> {
    let mut channels = sqlx::query_as::<_, NotificationChannel>(&format!(
        "SELECT {} FROM notification_channels ORDER BY created_at ASC",
        CHANNEL_COLUMNS
    ))
    .fetch_all(&state.pool)
    .await?;

    // Mask secrets if not admin (Mục 11)
    if user.0.role != UserRole::Admin {
        for ch in &mut channels {
            mask_sensitive_config(&mut ch.config_json);
        }
    }

    Ok(Json(ApiResponse::ok(channels)))
}

#[utoipa::path(
    post,
    path = "/api/notifications/channels",
    request_body = CreateNotificationChannelDto,
    responses(
        (status = 200, description = "Channel created", body = ApiResponse<NotificationChannel>),
        (status = 400, description = "Invalid channel configuration", body = ApiResponse<()>)
    ),
    tag = "Notifications",
    security(("bearer_auth" = []))
)]
pub async fn create_channel(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    Json(payload): Json<CreateNotificationChannelDto>,
) -> Result<Json<ApiResponse<NotificationChannel>>, AppError> {
    require_admin(&user)?;
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;
    validate_channel_config(payload.r#type, &payload.config_json).await?;

    let is_enabled = payload.is_enabled.unwrap_or(true);
    let channel = sqlx::query_as::<_, NotificationChannel>(&format!(
        r#"
        INSERT INTO notification_channels (name, type, config_json, min_severity, is_enabled)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING {}
        "#,
        CHANNEL_COLUMNS
    ))
    .bind(payload.name.trim())
    .bind(payload.r#type)
    .bind(payload.config_json)
    .bind(payload.min_severity)
    .bind(is_enabled)
    .fetch_one(&state.pool)
    .await?;

    audit::record(
        &state.pool,
        Some(user.0.sub),
        "CREATE_NOTIFICATION_CHANNEL",
        &channel.name,
        Some(client_ip.network()),
    )
    .await;

    Ok(Json(ApiResponse::ok(channel)))
}

#[utoipa::path(
    patch,
    path = "/api/notifications/channels/{id}",
    request_body = UpdateNotificationChannelDto,
    responses(
        (status = 200, description = "Channel updated", body = ApiResponse<NotificationChannel>),
        (status = 400, description = "Invalid channel configuration", body = ApiResponse<()>)
    ),
    tag = "Notifications",
    security(("bearer_auth" = []))
)]
pub async fn update_channel(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateNotificationChannelDto>,
) -> Result<Json<ApiResponse<NotificationChannel>>, AppError> {
    require_admin(&user)?;
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let current = sqlx::query_as::<_, NotificationChannel>(&format!(
        "SELECT {} FROM notification_channels WHERE id = $1",
        CHANNEL_COLUMNS
    ))
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Channel {} not found", id)))?;

    let config_changed = payload.config_json.is_some() || payload.r#type.is_some();
    let name = payload.name.unwrap_or(current.name);
    let channel_type = payload.r#type.unwrap_or(current.r#type);
    let config_json = payload.config_json.unwrap_or(current.config_json);
    let min_severity = payload.min_severity.unwrap_or(current.min_severity);
    let is_enabled = payload.is_enabled.unwrap_or(current.is_enabled);

    // Re-validate when the config changes or a channel gets (re-)enabled, so an invalid seed
    // channel cannot be switched on without being fixed first.
    if config_changed || (is_enabled && !current.is_enabled) {
        validate_channel_config(channel_type, &config_json).await?;
    }

    let updated = sqlx::query_as::<_, NotificationChannel>(&format!(
        r#"
        UPDATE notification_channels
        SET name = $1, type = $2, config_json = $3, min_severity = $4, is_enabled = $5, updated_at = CURRENT_TIMESTAMP
        WHERE id = $6
        RETURNING {}
        "#,
        CHANNEL_COLUMNS
    ))
    .bind(name.trim())
    .bind(channel_type)
    .bind(config_json)
    .bind(min_severity)
    .bind(is_enabled)
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    audit::record(
        &state.pool,
        Some(user.0.sub),
        "UPDATE_NOTIFICATION_CHANNEL",
        &updated.name,
        Some(client_ip.network()),
    )
    .await;

    Ok(Json(ApiResponse::ok(updated)))
}

#[utoipa::path(
    delete,
    path = "/api/notifications/channels/{id}",
    responses(
        (status = 200, description = "Channel deleted", body = ApiResponse<()>)
    ),
    tag = "Notifications",
    security(("bearer_auth" = []))
)]
pub async fn delete_channel(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    require_admin(&user)?;

    let name: String =
        sqlx::query_scalar("DELETE FROM notification_channels WHERE id = $1 RETURNING name")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("Channel {} not found", id)))?;

    audit::record(
        &state.pool,
        Some(user.0.sub),
        "DELETE_NOTIFICATION_CHANNEL",
        &name,
        Some(client_ip.network()),
    )
    .await;

    Ok(Json(ApiResponse::ok(())))
}

#[utoipa::path(
    post,
    path = "/api/notifications/test/{id}",
    responses(
        (status = 200, description = "Test alert sent", body = ApiResponse<String>),
        (status = 400, description = "Delivery failed (reason in error message)", body = ApiResponse<()>)
    ),
    tag = "Notifications",
    security(("bearer_auth" = []))
)]
pub async fn test_channel(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    require_admin(&user)?;

    let test_alert = Alert {
        id: Uuid::new_v4(),
        rule_id: None,
        severity: AlertSeverity::High,
        title: "Test Alert Dispatch".to_string(),
        description:
            "This is an automated test alert triggered from the Security Management Console."
                .to_string(),
        src_ip: "127.0.0.1".parse().expect("valid literal IP"),
        dst_ip: "10.0.0.1".parse().expect("valid literal IP"),
        detected_at: chrono::Utc::now(),
        status: AlertStatus::Open,
        acknowledged_by: None,
        resolved_at: None,
        mitre_tactic: Some("Discovery".to_string()),
        mitre_technique: Some("T1046".to_string()),
    };

    // Admins need the concrete delivery error to fix the channel, so surface it as a 400
    // rather than the generic, masked 500 message.
    state
        .alert_dispatcher
        .dispatch_single_channel(id, &test_alert)
        .await
        .map_err(|e| match e {
            AppError::Internal(msg) => AppError::BadRequest(format!("Test delivery failed: {}", msg)),
            other => other,
        })?;
    Ok(Json(ApiResponse::ok(format!(
        "Test alert delivered successfully via channel {}",
        id
    ))))
}
