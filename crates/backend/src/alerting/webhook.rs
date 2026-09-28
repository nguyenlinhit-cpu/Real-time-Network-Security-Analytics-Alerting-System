use common::models::{Alert, ChannelType};
use reqwest::Client;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use tracing::{error, info, warn};

use super::traits::NotificationChannel;
use crate::error::AppError;

/// Helper to verify if an IP address belongs to loopback, private, link-local, or restricted ranges
pub fn is_private_or_restricted_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 0.0.0.0/8 (current network)
            octets[0] == 0
                // 127.0.0.0/8 (loopback)
                || octets[0] == 127
                // 10.0.0.0/8 (private)
                || octets[0] == 10
                // 172.16.0.0/12 (private: 172.16.0.0 - 172.31.255.255)
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                // 192.168.0.0/16 (private)
                || (octets[0] == 192 && octets[1] == 168)
                // 169.254.0.0/16 (link-local, cloud metadata 169.254.169.254)
                || (octets[0] == 169 && octets[1] == 254)
                // 100.64.0.0/10 (carrier-grade NAT)
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                // 192.0.0.0/24 (IETF protocol assignments)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                // 198.18.0.0/15 (benchmarking)
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
                // 224.0.0.0/4 (multicast) & 240.0.0.0/4 (reserved) & broadcast
                || octets[0] >= 224
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            // ::1 (loopback)
            ipv6.is_loopback()
                // :: (unspecified)
                || ipv6.is_unspecified()
                // fe80::/10 (link-local)
                || (segments[0] & 0xffc0) == 0xfe80
                // fc00::/7 (unique local / private)
                || (segments[0] & 0xfe00) == 0xfc00
                // ff00::/8 (multicast)
                || (segments[0] & 0xff00) == 0xff00
                // IPv4-mapped IPv6 (::ffff:0:0/96)
                || if let Some(v4) = ipv6.to_ipv4_mapped() {
                    is_private_or_restricted_ip(IpAddr::V4(v4))
                } else {
                    false
                }
        }
    }
}

/// Validates webhook target URL to protect against Server-Side Request Forgery (SSRF)
pub async fn validate_webhook_url(
    url_str: &str,
    require_https: bool,
) -> Result<reqwest::Url, AppError> {
    validate_webhook_url_ext(url_str, require_https, false).await
}

pub async fn validate_webhook_url_ext(
    url_str: &str,
    require_https: bool,
    allow_private: bool,
) -> Result<reqwest::Url, AppError> {
    validate_and_resolve(url_str, require_https, allow_private)
        .await
        .map(|(url, _)| url)
}

/// Validates the URL and returns the vetted address its host resolved to. Callers must send the
/// request to exactly that address (see `pinned_client`) so a second DNS lookup cannot swap in a
/// private IP after validation (DNS rebinding).
pub async fn validate_and_resolve(
    url_str: &str,
    require_https: bool,
    allow_private: bool,
) -> Result<(reqwest::Url, Option<SocketAddr>), AppError> {
    let parsed = reqwest::Url::parse(url_str)
        .map_err(|e| AppError::BadRequest(format!("Invalid webhook URL format: {}", e)))?;

    let scheme = parsed.scheme();
    if require_https {
        if scheme != "https" {
            return Err(AppError::BadRequest(format!(
                "SSRF Protection: Webhook endpoint must use HTTPS scheme (received '{}')",
                scheme
            )));
        }
    } else if scheme != "https" && scheme != "http" {
        return Err(AppError::BadRequest(format!(
            "SSRF Protection: Webhook endpoint only supports HTTP/HTTPS (received '{}')",
            scheme
        )));
    }

    let host_str = parsed
        .host_str()
        .ok_or_else(|| AppError::BadRequest("Webhook URL must contain a valid host".to_string()))?;

    let mut pinned: Option<SocketAddr> = None;
    if !allow_private {
        // Block localhost literal strings and internal suffixes
        let lower_host = host_str.to_lowercase();
        if lower_host == "localhost"
            || lower_host.ends_with(".localhost")
            || lower_host.ends_with(".local")
            || lower_host.ends_with(".internal")
        {
            return Err(AppError::BadRequest(format!(
                "SSRF Protection: Access to internal host '{}' is blocked",
                host_str
            )));
        }

        // Direct IP parsing check
        if let Ok(ip) = host_str.parse::<IpAddr>() {
            if is_private_or_restricted_ip(ip) {
                return Err(AppError::BadRequest(format!(
                    "SSRF Protection: Access to private or restricted IP '{}' is blocked",
                    ip
                )));
            }
        } else {
            // DNS Resolution check
            let port = parsed
                .port_or_known_default()
                .unwrap_or(if scheme == "https" { 443 } else { 80 });
            let host_port = format!("{}:{}", host_str, port);

            let addrs = tokio::net::lookup_host(&host_port).await.map_err(|e| {
                AppError::BadRequest(format!(
                    "Failed to resolve webhook domain '{}': {}",
                    host_str, e
                ))
            })?;

            let mut found = false;
            for addr in addrs {
                found = true;
                pinned.get_or_insert(addr);
                let ip = addr.ip();
                if is_private_or_restricted_ip(ip) {
                    return Err(AppError::BadRequest(format!(
                        "SSRF Protection: Domain '{}' resolved to private or restricted IP '{}'",
                        host_str, ip
                    )));
                }
            }

            if !found {
                return Err(AppError::BadRequest(format!(
                    "SSRF Protection: No valid DNS resolution for host '{}'",
                    host_str
                )));
            }
        }
    }

    Ok((parsed, pinned))
}

/// HTTP client for outbound alert delivery: short timeout, no redirects (redirect-based SSRF)
/// and, when given, the host pinned to the address vetted by `validate_and_resolve`.
pub fn pinned_client(url: &reqwest::Url, pinned: Option<SocketAddr>) -> Client {
    let mut builder = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none());
    if let (Some(addr), Some(host)) = (pinned, url.host_str()) {
        builder = builder.resolve(host, addr);
    }
    builder.build().unwrap_or_default()
}

pub struct WebhookChannel {
    pub name: String,
    pub endpoint_url: String,
    pub require_https: bool,
    pub allow_private_ips: bool,
}

impl WebhookChannel {
    pub fn new(name: String, endpoint_url: String) -> Self {
        Self::with_options(name, endpoint_url, true)
    }

    pub fn with_options(name: String, endpoint_url: String, require_https: bool) -> Self {
        Self::with_full_options(name, endpoint_url, require_https, false)
    }

    pub fn with_full_options(
        name: String,
        endpoint_url: String,
        require_https: bool,
        allow_private_ips: bool,
    ) -> Self {
        Self {
            name,
            endpoint_url,
            require_https,
            allow_private_ips,
        }
    }
}

impl NotificationChannel for WebhookChannel {
    fn name(&self) -> &str {
        &self.name
    }

    fn channel_type(&self) -> ChannelType {
        ChannelType::Webhook
    }

    fn send<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>> {
        Box::pin(async move {
            // Validate URL against SSRF before firing request, then pin the vetted address.
            let (url, pinned) = match validate_and_resolve(
                &self.endpoint_url,
                self.require_https,
                self.allow_private_ips,
            )
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    error!("🚨 [SSRF BLOCKED] Webhook delivery aborted: {}", e);
                    return Err(e);
                }
            };
            let host = url.host_str().unwrap_or("?").to_string();

            info!(
                "🔗 [WEBHOOK ALERT] Posting incident to {}: {}",
                host, alert.title
            );

            let response = pinned_client(&url, pinned)
                .post(&self.endpoint_url)
                .json(alert)
                .send()
                .await;

            match response {
                Ok(res) if res.status().is_success() => {
                    info!("Webhook delivered successfully to {}", host);
                    Ok(())
                }
                Ok(res) => {
                    let status = res.status();
                    let body: String = res.text().await.unwrap_or_default().chars().take(300).collect();
                    let msg = format!(
                        "Webhook responded with non-2xx status code {}: {}",
                        status, body
                    );
                    warn!("{}", msg);
                    Err(AppError::Internal(msg))
                }
                Err(e) => {
                    let msg = format!("Webhook delivery failed: {}", e.without_url());
                    warn!("{}", msg);
                    Err(AppError::Internal(msg))
                }
            }
        })
    }
}
