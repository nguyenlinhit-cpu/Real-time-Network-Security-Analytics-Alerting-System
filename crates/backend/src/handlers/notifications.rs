use axum::{
    extract::{Path, State},
    Json,
};
use common::models::{
    Alert, AlertSeverity, AlertStatus, ChannelType, CreateNotificationChannelDto,
    NotificationChannel, UpdateNotificationChannelDto,
};
use common::ApiResponse;
use uuid::Uuid;
use validator::Validate;

use crate::{
    alerting::validate_webhook_url,
    auth::{middleware::CurrentUser, rbac::require_admin},
    error::AppError,
    state::AppState,
};

fn mask_sensitive_config(config: &mut serde_json::Value) {
    if let Some(obj) = config.as_object_mut() {
        for (k, v) in obj.iter_mut() {
            let lower = k.to_lowercase();
            if lower.contains("token")
                || lower.contains("password")
                || lower.contains("secret")
                || lower.contains("key")
            {
                *v = serde_json::json!("********");
            }
        }
    }
}

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
    let mut channels = sqlx::query_as::<_, NotificationChannel>(
        r#"
        SELECT id, name, type, config_json, min_severity, is_enabled, created_at, updated_at
        FROM notification_channels
        ORDER BY created_at ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    // Mask secrets if not admin (Mục 11)
    if user.0.role != common::models::UserRole::Admin {
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
        (status = 201, description = "Channel created", body = ApiResponse<NotificationChannel>)
    ),
    tag = "Notifications",
    security(("bearer_auth" = []))
)]
pub async fn create_channel(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(payload): Json<CreateNotificationChannelDto>,
) -> Result<Json<ApiResponse<NotificationChannel>>, AppError> {
    require_admin(&user)?;
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    // SSRF Protection: Validate webhook / slack endpoints
    if payload.r#type == ChannelType::Webhook {
        if let Some(url) = payload
            .config_json
            .get("endpoint_url")
            .and_then(|v| v.as_str())
        {
            validate_webhook_url(url, true).await?;
        }
    } else if payload.r#type == ChannelType::Slack {
        if let Some(url) = payload
            .config_json
            .get("webhook_url")
            .and_then(|v| v.as_str())
        {
            validate_webhook_url(url, true).await?;
        }
    }

    let is_enabled = payload.is_enabled.unwrap_or(true);
    let channel = sqlx::query_as::<_, NotificationChannel>(
        r#"
        INSERT INTO notification_channels (name, type, config_json, min_severity, is_enabled)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, name, type, config_json, min_severity, is_enabled, created_at, updated_at
        "#,
    )
    .bind(payload.name)
    .bind(payload.r#type)
    .bind(payload.config_json)
    .bind(payload.min_severity)
    .bind(is_enabled)
    .fetch_one(&state.pool)
    .await?;

    let _ = sqlx::query!(
        "INSERT INTO audit_logs (user_id, action, target) VALUES ($1, $2, $3)",
        user.0.sub,
        "CREATE_NOTIFICATION_CHANNEL",
        channel.name
    )
    .execute(&state.pool)
    .await;

    Ok(Json(ApiResponse::ok(channel)))
}

#[utoipa::path(
    patch,
    path = "/api/notifications/channels/{id}",
    request_body = UpdateNotificationChannelDto,
    responses(
        (status = 200, description = "Channel updated", body = ApiResponse<NotificationChannel>)
    ),
    tag = "Notifications",
    security(("bearer_auth" = []))
)]
pub async fn update_channel(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateNotificationChannelDto>,
) -> Result<Json<ApiResponse<NotificationChannel>>, AppError> {
    require_admin(&user)?;
    payload
        .validate()
        .map_err(|e| AppError::ValidationError(e.to_string()))?;

    let current = sqlx::query_as::<_, NotificationChannel>(
        r#"
        SELECT id, name, type, config_json, min_severity, is_enabled, created_at, updated_at
        FROM notification_channels WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Channel {} not found", id)))?;

    let name = payload.name.unwrap_or(current.name);
    let channel_type = payload.r#type.unwrap_or(current.r#type);
    let config_json = payload.config_json.unwrap_or(current.config_json);
    let min_severity = payload.min_severity.unwrap_or(current.min_severity);
    let is_enabled = payload.is_enabled.unwrap_or(current.is_enabled);

    // SSRF Protection: Validate webhook / slack endpoints
    if channel_type == ChannelType::Webhook {
        if let Some(url) = config_json.get("endpoint_url").and_then(|v| v.as_str()) {
            validate_webhook_url(url, true).await?;
        }
    } else if channel_type == ChannelType::Slack {
        if let Some(url) = config_json.get("webhook_url").and_then(|v| v.as_str()) {
            validate_webhook_url(url, true).await?;
        }
    }

    let updated = sqlx::query_as::<_, NotificationChannel>(
        r#"
        UPDATE notification_channels
        SET name = $1, type = $2, config_json = $3, min_severity = $4, is_enabled = $5, updated_at = CURRENT_TIMESTAMP
        WHERE id = $6
        RETURNING id, name, type, config_json, min_severity, is_enabled, created_at, updated_at
        "#,
    )
    .bind(&name)
    .bind(channel_type)
    .bind(config_json)
    .bind(min_severity)
    .bind(is_enabled)
    .bind(id)
    .fetch_one(&state.pool)
    .await?;

    let _ = sqlx::query!(
        "INSERT INTO audit_logs (user_id, action, target) VALUES ($1, $2, $3)",
        user.0.sub,
        "UPDATE_NOTIFICATION_CHANNEL",
        updated.name
    )
    .execute(&state.pool)
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
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    require_admin(&user)?;

    let res = sqlx::query("DELETE FROM notification_channels WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("Channel {} not found", id)));
    }

    let _ = sqlx::query!(
        "INSERT INTO audit_logs (user_id, action, target) VALUES ($1, $2, $3)",
        user.0.sub,
        "DELETE_NOTIFICATION_CHANNEL",
        id.to_string()
    )
    .execute(&state.pool)
    .await;

    Ok(Json(ApiResponse::ok(())))
}

#[utoipa::path(
    post,
    path = "/api/notifications/test/{id}",
    responses(
        (status = 200, description = "Test alert sent", body = ApiResponse<String>)
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
        src_ip: "127.0.0.1".parse().unwrap(),
        dst_ip: "10.0.0.1".parse().unwrap(),
        detected_at: chrono::Utc::now(),
        status: AlertStatus::Open,
        acknowledged_by: None,
        resolved_at: None,
    };

    state
        .alert_dispatcher
        .dispatch_single_channel(id, &test_alert)
        .await?;
    Ok(Json(ApiResponse::ok(format!(
        "Dispatched test alert successfully for channel {}",
        id
    ))))
}
