use backend::alerting::throttler::AlertThrottler;
use backend::alerting::traits::NotificationChannel;
use chrono::Utc;
use common::models::{Alert, AlertSeverity, AlertStatus};
use ipnetwork::IpNetwork;
use uuid::Uuid;

fn create_sample_alert(severity: AlertSeverity) -> Alert {
    Alert {
        id: Uuid::new_v4(),
        rule_id: Some(Uuid::new_v4()),
        severity,
        title: "Test Security Incident".to_string(),
        description: "Test incident description for verification".to_string(),
        src_ip: "10.0.0.99/32".parse().unwrap(),
        dst_ip: "192.168.1.50/32".parse().unwrap(),
        detected_at: Utc::now(),
        status: AlertStatus::Open,
        acknowledged_by: None,
        resolved_at: None,
    }
}

#[test]
fn test_alert_throttler_deduplication() {
    let throttler = AlertThrottler::new(60);
    let rule_id = Some(Uuid::new_v4());
    let src_ip: IpNetwork = "192.168.1.200/32".parse().unwrap();

    // First time should not be throttled
    assert!(!throttler.should_throttle(rule_id, src_ip), "First alert must not be throttled");

    // Immediate second time with same rule_id and src_ip MUST be throttled
    assert!(throttler.should_throttle(rule_id, src_ip), "Immediate duplicate alert must be throttled");

    // Different source IP should NOT be throttled
    let other_ip: IpNetwork = "192.168.1.201/32".parse().unwrap();
    assert!(!throttler.should_throttle(rule_id, other_ip), "Different IP must not be throttled");
}

#[tokio::test]
async fn test_webhook_channel_dispatch() {
    let alert = create_sample_alert(AlertSeverity::High);
    let webhook = backend::alerting::webhook::WebhookChannel::new(
        "Dummy Webhook".to_string(),
        "http://127.0.0.1:9999/dummy-webhook".to_string(),
    );
    
    // Webhook rejects loopback IP 127.0.0.1 due to SSRF protection
    let result = webhook.send(&alert).await;
    assert!(result.is_err(), "Loopback webhook target must be rejected by SSRF protection");
}

