use common::models::{Alert, ChannelType, NotificationChannel as ChannelModel};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use super::{
    email::EmailChannel, slack::SlackChannel, telegram::TelegramChannel, throttler::AlertThrottler,
    traits::NotificationChannel, webhook::WebhookChannel,
};
use crate::error::AppError;

fn build_channel(ch: &ChannelModel) -> Box<dyn NotificationChannel> {
    match ch.r#type {
        ChannelType::Email => {
            let host = ch.config_json["smtp_host"]
                .as_str()
                .unwrap_or("localhost")
                .to_string();
            let port = ch.config_json["smtp_port"].as_u64().unwrap_or(587) as u16;
            let to = ch.config_json["to_email"]
                .as_str()
                .unwrap_or("alerts@secnet.local")
                .to_string();
            let username = ch.config_json["smtp_username"]
                .as_str()
                .or_else(|| ch.config_json["username"].as_str())
                .map(|s| s.to_string());
            let password = ch.config_json["smtp_password"]
                .as_str()
                .or_else(|| ch.config_json["password"].as_str())
                .map(|s| s.to_string());
            let from = ch.config_json["from_email"]
                .as_str()
                .unwrap_or("noreply@secnet.local")
                .to_string();
            Box::new(EmailChannel {
                name: ch.name.clone(),
                smtp_host: host,
                smtp_port: port,
                username,
                password,
                from_email: from,
                to_email: to,
            })
        }
        ChannelType::Webhook => {
            let url = ch.config_json["endpoint_url"]
                .as_str()
                .unwrap_or("http://localhost:9000/webhook")
                .to_string();
            Box::new(WebhookChannel::new(ch.name.clone(), url))
        }
        ChannelType::Telegram => {
            let token = ch.config_json["bot_token"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let chat_id = ch.config_json["chat_id"].as_str().unwrap_or("").to_string();
            Box::new(TelegramChannel::new(ch.name.clone(), token, chat_id))
        }
        ChannelType::Slack => {
            let url = ch.config_json["webhook_url"]
                .as_str()
                .unwrap_or("")
                .to_string();
            Box::new(SlackChannel::new(ch.name.clone(), url))
        }
    }
}

pub struct AlertDispatcher {
    pool: PgPool,
    throttler: Arc<AlertThrottler>,
}

impl AlertDispatcher {
    pub fn new(pool: PgPool, deduplication_seconds: u64) -> Self {
        Self::with_redis(pool, deduplication_seconds, None)
    }

    pub fn with_redis(
        pool: PgPool,
        deduplication_seconds: u64,
        redis: Option<Arc<crate::redis_client::SimpleRedisClient>>,
    ) -> Self {
        Self {
            pool,
            throttler: Arc::new(AlertThrottler::with_redis(deduplication_seconds, redis)),
        }
    }

    /// Dispatch alert to a single channel by ID without throttling (used for channel testing) (Mục 36)
    pub async fn dispatch_single_channel(
        &self,
        channel_id: Uuid,
        alert: &Alert,
    ) -> Result<(), AppError> {
        let ch = sqlx::query_as::<_, ChannelModel>(
            "SELECT id, name, type, config_json, min_severity, is_enabled, created_at, updated_at FROM notification_channels WHERE id = $1"
        )
        .bind(channel_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Channel {} not found", channel_id)))?;

        let channel = build_channel(&ch);
        let result = channel.send(alert).await;

        let status_str = if result.is_ok() { "SUCCESS" } else { "FAILED" };
        let _ = sqlx::query!(
            "INSERT INTO audit_logs (action, target) VALUES ($1, $2)",
            format!("ALERT_TEST_{}:{}", ch.name, status_str),
            alert.title
        )
        .execute(&self.pool)
        .await;

        result
    }

    /// Dispatch alert to all matching, enabled notification channels concurrently
    pub async fn dispatch(&self, alert: &Alert) -> Result<(), AppError> {
        // 1. Throttling / Deduplication check (distributed via Redis if active)
        if self
            .throttler
            .should_throttle_async(alert.rule_id, alert.src_ip)
            .await
        {
            info!(
                "Suppressed duplicate alert for rule {:?} from source IP {}",
                alert.rule_id, alert.src_ip
            );
            return Ok(());
        }

        // 2. Fetch enabled notification channels from DB
        let db_channels = sqlx::query_as::<_, ChannelModel>(
            "SELECT id, name, type, config_json, min_severity, is_enabled, created_at, updated_at FROM notification_channels WHERE is_enabled = true"
        )
        .fetch_all(&self.pool)
        .await?;

        // 3. Build channels matching min_severity
        let mut active_channels: Vec<Box<dyn NotificationChannel>> = Vec::new();
        for ch in db_channels {
            if alert.severity >= ch.min_severity {
                active_channels.push(build_channel(&ch));
            }
        }

        // 4. Dispatch concurrently so failure of one channel doesn't block others
        let mut tasks = Vec::new();
        for channel in active_channels {
            let alert_clone = alert.clone();
            let pool_clone = self.pool.clone();

            tasks.push(tokio::spawn(async move {
                let ch_name = channel.name().to_string();
                let result = channel.send(&alert_clone).await;

                let status_str = if result.is_ok() { "SUCCESS" } else { "FAILED" };
                let _ = sqlx::query!(
                    "INSERT INTO audit_logs (action, target) VALUES ($1, $2)",
                    format!("ALERT_NOTIFICATION_{}:{}", ch_name, status_str),
                    alert_clone.title
                )
                .execute(&pool_clone)
                .await;

                if let Err(e) = result {
                    warn!("Channel '{}' dispatch failed: {}", ch_name, e);
                }
            }));
        }

        for task in tasks {
            let _ = task.await;
        }

        Ok(())
    }
}
