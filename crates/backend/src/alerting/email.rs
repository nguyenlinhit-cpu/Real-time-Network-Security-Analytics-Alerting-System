use common::models::{Alert, ChannelType};
use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use std::future::Future;
use std::pin::Pin;
use tracing::{info, warn};

use super::traits::NotificationChannel;
use crate::error::AppError;

pub struct EmailChannel {
    pub name: String,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from_email: String,
    pub to_email: String,
}

impl NotificationChannel for EmailChannel {
    fn name(&self) -> &str {
        &self.name
    }

    fn channel_type(&self) -> ChannelType {
        ChannelType::Email
    }

    fn send<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>> {
        Box::pin(async move {
            let subject = format!("[SecNet Alert - {:?}] {}", alert.severity, alert.title);
            let body = format!(
                "--- SECURITY INCIDENT ALERT ---\n\
                 Severity: {:?}\n\
                 Title: {}\n\
                 Description: {}\n\
                 Source IP: {}\n\
                 Target IP: {}\n\
                 Detected At: {}\n\
                 Incident ID: {}\n\
                 -------------------------------",
                alert.severity,
                alert.title,
                alert.description,
                alert.src_ip,
                alert.dst_ip,
                alert.detected_at,
                alert.id
            );

            let email = Message::builder()
                .from(
                    self.from_email
                        .parse()
                        .map_err(|e| AppError::Internal(format!("Invalid from email: {}", e)))?,
                )
                .to(self
                    .to_email
                    .parse()
                    .map_err(|e| AppError::Internal(format!("Invalid to email: {}", e)))?)
                .subject(subject)
                .header(ContentType::TEXT_PLAIN)
                .body(body)
                .map_err(|e| AppError::Internal(format!("Failed to build email message: {}", e)))?;

            info!(
                "📧 [EMAIL ALERT] Dispatching to {}: {}",
                self.to_email, alert.title
            );

            let mut mailer_builder =
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.smtp_host)
                    .port(self.smtp_port);

            if let (Some(u), Some(p)) = (&self.username, &self.password) {
                mailer_builder = mailer_builder.credentials(Credentials::new(u.clone(), p.clone()));
            }

            let mailer = mailer_builder.build();

            match mailer.send(email).await {
                Ok(_) => {
                    info!("Email alert successfully delivered to {}", self.to_email);
                    Ok(())
                }
                Err(e) => {
                    let msg = format!("SMTP delivery failed: {}", e);
                    warn!("{}", msg);
                    Err(AppError::Internal(msg))
                }
            }
        })
    }
}
