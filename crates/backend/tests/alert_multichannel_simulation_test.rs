use axum::{http::StatusCode, routing::post, Router};
use backend::alerting::{
    email::EmailChannel, telegram::TelegramChannel, throttler::AlertThrottler,
    traits::NotificationChannel, webhook::WebhookChannel,
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
        mitre_tactic: Some("Exfiltration".to_string()),
        mitre_technique: Some("T1071.004".to_string()),
    }
}

#[tokio::test]
async fn test_multi_channel_alert_simulation() {
    let alert = make_test_alert(AlertSeverity::Critical, "192.168.1.250/32");

    // Start local mock HTTP server (Mục 56 - no external requests)
    let mock_app = Router::new()
        .route(
            "/webhook",
            post(|| async { (StatusCode::OK, "{\"status\":\"ok\"}") }),
        )
        .route(
            "/bot123456789:MOCK_TOKEN/sendMessage",
            post(|| async { (StatusCode::OK, "{\"ok\":true}") }),
        )
        .route(
            "/bot_error:FAIL_TOKEN/sendMessage",
            post(|| async {
                (
                    StatusCode::BAD_REQUEST,
                    "{\"ok\":false,\"description\":\"bad request\"}",
                )
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, mock_app).await.unwrap();
    });

    // 1. Email Channel Test (Unreachable SMTP must return error - Mục 36)
    let email_ch = EmailChannel {
        name: "Security Operations Email".to_string(),
        smtp_host: "127.0.0.1".to_string(),
        smtp_port: 25255, // non-listening port
        username: None,
        password: None,
        from_email: "alerts@secnet.local".to_string(),
        to_email: "soc@secnet.local".to_string(),
        security: backend::alerting::email::SmtpSecurity::None,
    };
    assert_eq!(email_ch.name(), "Security Operations Email");
    let email_res = email_ch.send(&alert).await;
    assert!(
        email_res.is_err(),
        "Unreachable SMTP server must return error instead of Ok"
    );

    // 2. Webhook Channel Test with mock server
    let webhook_mock = WebhookChannel::with_full_options(
        "SIEM Webhook".to_string(),
        format!("http://127.0.0.1:{}/webhook", port),
        false,
        true, // allow loopback for test
    );
    assert_eq!(webhook_mock.name(), "SIEM Webhook");
    let webhook_mock_res = webhook_mock.send(&alert).await;
    assert!(
        webhook_mock_res.is_ok(),
        "Webhook delivery to mock server must succeed: {:?}",
        webhook_mock_res
    );

    // 3. Webhook SSRF Protection Test (Default must block 127.0.0.1)
    let webhook_ssrf_blocked = WebhookChannel::with_options(
        "SIEM Webhook SSRF Test".to_string(),
        format!("http://127.0.0.1:{}/webhook", port),
        false, // http allowed, but private IP must be blocked
    );
    let ssrf_res = webhook_ssrf_blocked.send(&alert).await;
    assert!(
        ssrf_res.is_err(),
        "SSRF protection must block private/loopback IPs by default"
    );

    // 4. Telegram Channel Test with mock server
    let telegram_mock = TelegramChannel::with_base_url(
        "Telegram SOC Feed".to_string(),
        "123456789:MOCK_TOKEN".to_string(),
        "-1001234567890".to_string(),
        format!("http://127.0.0.1:{}", port),
    );
    assert_eq!(telegram_mock.name(), "Telegram SOC Feed");
    let tg_mock_res = telegram_mock.send(&alert).await;
    assert!(
        tg_mock_res.is_ok(),
        "Telegram delivery to mock server must succeed: {:?}",
        tg_mock_res
    );

    // 5. Telegram Error Handling Test (4xx/5xx must return Err - Mục 36)
    let telegram_fail = TelegramChannel::with_base_url(
        "Telegram Failing Feed".to_string(),
        "FAIL_TOKEN".to_string(),
        "-1001234567890".to_string(),
        format!("http://127.0.0.1:{}", port),
    );
    let tg_fail_res = telegram_fail.send(&alert).await;
    assert!(
        tg_fail_res.is_err(),
        "Telegram non-2xx status must return error instead of Ok"
    );
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
