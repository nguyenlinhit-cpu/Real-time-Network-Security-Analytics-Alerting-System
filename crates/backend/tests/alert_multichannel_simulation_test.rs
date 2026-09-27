use backend::alerting::{
    email::EmailChannel,
    telegram::TelegramChannel,
    throttler::AlertThrottler,
    traits::NotificationChannel,
    webhook::WebhookChannel,
};
use chrono::Utc;
use common::models::{Alert, AlertSeverity, AlertStatus};
use ipnetwork::IpNetwork;
use uuid::Uuid;

fn make_test_alert(severity: AlertSeverity, src_ip: &str) -> Alert {
    Alert {
        id: Uuid::new_v4(),
        rule_id: Some(Uuid::new_v4()),
        severity,
        title: "CRITICAL: Potential Data Exfiltration".to_string(),
        description: "Suspicious DNS tunneling detected towards rogue nameserver".to_string(),
        src_ip: src_ip.parse().unwrap(),
        dst_ip: "8.8.8.8/32".parse().unwrap(),
        detected_at: Utc::now(),
        status: AlertStatus::Open,
        acknowledged_by: None,
        resolved_at: None,
    }
}

#[tokio::test]
async fn test_multi_channel_alert_simulation() {
    let alert = make_test_alert(AlertSeverity::Critical, "192.168.1.250/32");

    // 1. Email Channel Test
    let email_ch = EmailChannel {
        name: "Security Operations Email".to_string(),
        smtp_host: "127.0.0.1".to_string(),
        smtp_port: 2525,
        username: None,
        password: None,
        from_email: "alerts@secnet.local".to_string(),
        to_email: "soc@secnet.local".to_string(),
    };
    assert_eq!(email_ch.name(), "Security Operations Email");
    let email_res = email_ch.send(&alert).await;
    assert!(email_res.is_ok(), "Email dispatch fallback must handle local dev cleanly");

    // 2. Webhook Channel Test
    let webhook_ch = WebhookChannel::new(
        "SIEM Webhook".to_string(),
        "https://93.184.216.34:9999/api/v1/alerts".to_string(),
    );
    assert_eq!(webhook_ch.name(), "SIEM Webhook");
    let webhook_res = webhook_ch.send(&alert).await;
    assert!(webhook_res.is_ok(), "Webhook dispatch must handle unreachable target gracefully");

    // 3. Telegram Channel Test
    let telegram_ch = TelegramChannel::new(
        "Telegram SOC Feed".to_string(),
        "123456789:MOCK_TOKEN".to_string(),
        "-1001234567890".to_string(),
    );
    assert_eq!(telegram_ch.name(), "Telegram SOC Feed");
    let tg_res = telegram_ch.send(&alert).await;
    assert!(tg_res.is_ok(), "Telegram dispatch must handle mock token gracefully");
}

#[test]
fn test_throttler_window_deduplication() {
    let throttler = AlertThrottler::new(30);
    let rule = Some(Uuid::new_v4());
    let attacker_ip: IpNetwork = "10.0.0.99/32".parse().unwrap();

    // 1st time: allowed
    assert!(!throttler.should_throttle(rule, attacker_ip));

    // 2nd time immediate: throttled
    assert!(throttler.should_throttle(rule, attacker_ip));

    // Another IP: allowed
    let attacker_ip2: IpNetwork = "10.0.0.100/32".parse().unwrap();
    assert!(!throttler.should_throttle(rule, attacker_ip2));
}
