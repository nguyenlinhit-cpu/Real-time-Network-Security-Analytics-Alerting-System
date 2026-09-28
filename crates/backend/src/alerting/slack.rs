use common::models::{Alert, ChannelType};
use reqwest::Client;
use serde_json::json;
use std::future::Future;
use std::pin::Pin;
use tracing::{error, info, warn};

use super::traits::NotificationChannel;
use super::webhook::validate_webhook_url_ext;
use crate::error::AppError;

pub struct SlackChannel {
    pub name: String,
    pub webhook_url: String,
    pub client: Client,
    pub allow_private_ips: bool,
}

impl SlackChannel {
    pub fn new(name: String, webhook_url: String) -> Self {
        Self {
            name,
            webhook_url,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            allow_private_ips: false,
        }
    }
}

impl NotificationChannel for SlackChannel {
    fn name(&self) -> &str {
        &self.name
    }

    fn channel_type(&self) -> ChannelType {
        ChannelType::Slack
    }

    fn send<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>> {
        Box::pin(async move {
            if let Err(e) =
                validate_webhook_url_ext(&self.webhook_url, true, self.allow_private_ips).await
            {
                error!(
                    "🚨 [SSRF BLOCKED] Slack delivery aborted for {}: {}",
                    self.webhook_url, e
                );
                return Err(e);
            }

            let text = format!(
                "🚨 *[SecNet Alert - {:?}]* *{}*\n_{}_\n• *Source IP:* `{}`\n• *Target IP:* `{}`\n• *Time:* `{}`",
                alert.severity,
                alert.title,
                alert.description,
                alert.src_ip,
                alert.dst_ip,
                alert.detected_at.to_rfc3339()
            );

            let payload = json!({
                "text": text,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": text
                        }
                    }
                ]
            });

            info!(
                "📢 [SLACK ALERT] Dispatching to Slack webhook: {}",
                alert.title
            );

            let response = self
                .client
                .post(&self.webhook_url)
                .json(&payload)
                .send()
                .await;

            match response {
                Ok(res) if res.status().is_success() => {
                    info!("Slack alert successfully delivered");
                    Ok(())
                }
                Ok(res) => {
                    let status = res.status();
                    let body = res.text().await.unwrap_or_default();
                    let msg = format!("Slack webhook error {}: {}", status, body);
                    warn!("{}", msg);
                    Err(AppError::Internal(msg))
                }
                Err(e) => {
                    let msg = format!("Slack delivery failed: {}", e);
                    warn!("{}", msg);
                    Err(AppError::Internal(msg))
                }
            }
        })
    }
}
