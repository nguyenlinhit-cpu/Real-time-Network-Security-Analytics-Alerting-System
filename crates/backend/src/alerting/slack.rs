use common::models::{Alert, ChannelType};
use serde_json::json;
use std::future::Future;
use std::pin::Pin;
use tracing::{error, info, warn};

use super::traits::NotificationChannel;
use super::webhook::{pinned_client, validate_and_resolve};
use crate::error::AppError;

pub struct SlackChannel {
    pub name: String,
    pub webhook_url: String,
    pub allow_private_ips: bool,
}

impl SlackChannel {
    pub fn new(name: String, webhook_url: String) -> Self {
        Self {
            name,
            webhook_url,
            allow_private_ips: false,
        }
    }
}

/// Slack mrkdwn control characters must be escaped so alert text cannot inject links/mentions.
fn escape_mrkdwn(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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
            let (url, pinned) =
                match validate_and_resolve(&self.webhook_url, true, self.allow_private_ips).await {
                    Ok(v) => v,
                    Err(e) => {
                        error!("🚨 [SSRF BLOCKED] Slack delivery aborted: {}", e);
                        return Err(e);
                    }
                };

            let text = format!(
                "🚨 *[SecNet Alert - {:?}]* *{}*\n_{}_\n• *Source IP:* `{}`\n• *Target IP:* `{}`\n• *Time:* `{}`",
                alert.severity,
                escape_mrkdwn(&alert.title),
                escape_mrkdwn(&alert.description),
                alert.src_ip.ip(),
                alert.dst_ip.ip(),
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

            let response = pinned_client(&url, pinned)
                .post(url.clone())
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
                    let body: String = res
                        .text()
                        .await
                        .unwrap_or_default()
                        .chars()
                        .take(300)
                        .collect();
                    let msg = format!("Slack webhook error {}: {}", status, body);
                    warn!("{}", msg);
                    Err(AppError::Internal(msg))
                }
                Err(e) => {
                    // without_url(): the Slack webhook URL itself is a secret.
                    let msg = format!("Slack delivery failed: {}", e.without_url());
                    warn!("{}", msg);
                    Err(AppError::Internal(msg))
                }
            }
        })
    }
}
