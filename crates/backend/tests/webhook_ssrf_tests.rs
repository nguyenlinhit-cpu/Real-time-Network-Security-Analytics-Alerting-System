use backend::alerting::{is_private_or_restricted_ip, validate_webhook_url, WebhookChannel};
use backend::alerting::traits::NotificationChannel;
use chrono::Utc;
use common::models::{Alert, AlertSeverity, AlertStatus};
use std::net::IpAddr;
use uuid::Uuid;

fn sample_alert() -> Alert {
    Alert {
        id: Uuid::new_v4(),
        rule_id: None,
        severity: AlertSeverity::High,
        title: "Security Incident Alert".to_string(),
        description: "Testing SSRF protection in webhook alerting pipeline".to_string(),
        src_ip: "203.0.113.10/32".parse().unwrap(),
        dst_ip: "198.51.100.20/32".parse().unwrap(),
        detected_at: Utc::now(),
        status: AlertStatus::Open,
        acknowledged_by: None,
        resolved_at: None,
    }
}

#[test]
fn test_is_private_or_restricted_ip_ipv4() {
    // Loopback
    assert!(is_private_or_restricted_ip("127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_private_or_restricted_ip("127.0.0.2".parse::<IpAddr>().unwrap()));

    // Private IPv4 (RFC 1918)
    assert!(is_private_or_restricted_ip("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_private_or_restricted_ip("10.255.255.255".parse::<IpAddr>().unwrap()));
    assert!(is_private_or_restricted_ip("172.16.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_private_or_restricted_ip("172.31.255.254".parse::<IpAddr>().unwrap()));
    assert!(is_private_or_restricted_ip("192.168.1.1".parse::<IpAddr>().unwrap()));
    assert!(is_private_or_restricted_ip("192.168.100.50".parse::<IpAddr>().unwrap()));

    // Link-local & Cloud Metadata endpoint
    assert!(is_private_or_restricted_ip("169.254.169.254".parse::<IpAddr>().unwrap()));
    assert!(is_private_or_restricted_ip("169.254.1.1".parse::<IpAddr>().unwrap()));

    // Carrier Grade NAT (100.64.0.0/10)
    assert!(is_private_or_restricted_ip("100.64.0.1".parse::<IpAddr>().unwrap()));

    // Public IPs should NOT be restricted
    assert!(!is_private_or_restricted_ip("8.8.8.8".parse::<IpAddr>().unwrap()));
    assert!(!is_private_or_restricted_ip("1.1.1.1".parse::<IpAddr>().unwrap()));
    assert!(!is_private_or_restricted_ip("142.250.190.46".parse::<IpAddr>().unwrap()));
}

#[test]
fn test_is_private_or_restricted_ip_ipv6() {
    // IPv6 Loopback
    assert!(is_private_or_restricted_ip("::1".parse::<IpAddr>().unwrap()));

    // IPv6 Link-Local
    assert!(is_private_or_restricted_ip("fe80::1".parse::<IpAddr>().unwrap()));

    // IPv6 Unique Local Address (ULA)
    assert!(is_private_or_restricted_ip("fc00::1".parse::<IpAddr>().unwrap()));
    assert!(is_private_or_restricted_ip("fd12:3456:789a:1::1".parse::<IpAddr>().unwrap()));

    // Public IPv6 should NOT be restricted
    assert!(!is_private_or_restricted_ip("2606:4700:4700::1111".parse::<IpAddr>().unwrap()));
    assert!(!is_private_or_restricted_ip("2001:4860:4860::8888".parse::<IpAddr>().unwrap()));
}

#[tokio::test]
async fn test_validate_webhook_url_blocks_internal_destinations() {
    // Rejects localhost
    assert!(validate_webhook_url("http://localhost:8080/hook", false).await.is_err());
    assert!(validate_webhook_url("https://localhost:8443/hook", false).await.is_err());
    assert!(validate_webhook_url("https://service.internal/hook", false).await.is_err());

    // Rejects loopback & private IPv4
    assert!(validate_webhook_url("http://127.0.0.1:8080/hook", false).await.is_err());
    assert!(validate_webhook_url("http://10.0.0.5:9000/hook", false).await.is_err());
    assert!(validate_webhook_url("http://192.168.1.10/hook", false).await.is_err());

    // Rejects AWS/GCP/Azure Cloud Metadata IP (169.254.169.254)
    assert!(validate_webhook_url("http://169.254.169.254/latest/meta-data", false).await.is_err());

    // Rejects non-HTTP(S) schemes
    assert!(validate_webhook_url("file:///etc/passwd", false).await.is_err());
    assert!(validate_webhook_url("gopher://127.0.0.1:70", false).await.is_err());

    // Rejects HTTP when HTTPS is strictly enforced
    assert!(validate_webhook_url("http://example.com/webhook", true).await.is_err());
}

#[tokio::test]
async fn test_webhook_channel_aborts_on_ssrf_target() {
    let alert = sample_alert();
    let channel = WebhookChannel::new(
        "Malicious Webhook Test".to_string(),
        "http://127.0.0.1:8080/api/internal".to_string(),
    );

    // Dispatch should be aborted before any HTTP network connection is made
    let result = channel.send(&alert).await;
    assert!(result.is_err(), "WebhookChannel must reject internal loopback destination");
}
