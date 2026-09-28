use common::models::{Alert, ChannelType};
use reqwest::Client;
use serde_json::json;
use std::future::Future;
use std::pin::Pin;
use tracing::{info, warn};

use super::traits::NotificationChannel;
use crate::error::AppError;

pub struct TelegramChannel {
    pub name: String,
    pub bot_token: String,
    pub chat_id: String,
    pub client: Client,
    pub base_url: String,
}

impl TelegramChannel {
    pub fn new(name: String, bot_token: String, chat_id: String) -> Self {
        Self::with_base_url(
            name,
            bot_token,
            chat_id,
            "https://api.telegram.org".to_string(),
        )
    }

    pub fn with_base_url(
        name: String,
        bot_token: String,
        chat_id: String,
        base_url: String,
    ) -> Self {
        Self {
            name,
            bot_token,
            chat_id,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            base_url,
        }
    }
}

impl NotificationChannel for TelegramChannel {
    fn name(&self) -> &str {
        &self.name
    }

    fn channel_type(&self) -> ChannelType {
        ChannelType::Telegram
    }

    fn send<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>> {
        Box::pin(async move {
            let url = format!(
                "{}/bot{}/sendMessage",
                self.base_url.trim_end_matches('/'),
                self.bot_token
            );
            let text = format!(
                "🚨 *[SecNet Security Alert]*\n\
                 *Severity:* `{:?}`\n\
                 *Title:* {}\n\
                 *Description:* {}\n\
                 *Source IP:* `{}`\n\
                 *Target IP:* `{}`\n\
                 *Detected:* `{}`",
                alert.severity,
                alert.title,
                alert.description,
                alert.src_ip,
                alert.dst_ip,
                alert.detected_at.to_rfc3339()
            );

            let payload = json!({
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": "Markdown"
            });

            info!(
                "📱 [TELEGRAM ALERT] Dispatching to Telegram chat {}: {}",
                self.chat_id, alert.title
            );

            let response = self.client.post(&url).json(&payload).send().await;

            match response {
                Ok(res) if res.status().is_success() => {
                    info!("Telegram alert successfully delivered to {}", self.chat_id);
                    Ok(())
                }
                Ok(res) => {
                    let status = res.status();
                    let body = res.text().await.unwrap_or_default();
                    let msg = format!(
                        "Telegram API responded with error status {}: {}",
                        status, body
                    );
                    warn!("{}", msg);
                    Err(AppError::Internal(msg))
                }
                Err(e) => {
                    let msg = format!("Telegram API request failed: {}", e);
                    warn!("{}", msg);
                    Err(AppError::Internal(msg))
                }
            }
        })
    }
}
