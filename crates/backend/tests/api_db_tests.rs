//! End-to-end handler tests against a real PostgreSQL/TimescaleDB database.
//!
//! Set `DATABASE_URL` (e.g. the docker-compose TimescaleDB) to run them; without it every test
//! is skipped so `cargo test` still works offline. Migrations are applied automatically.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use backend::{alerting::AlertDispatcher, create_router, AppState};
use common::models::User;
use dashmap::DashMap;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::{broadcast, OnceCell};
use tower::ServiceExt;
use uuid::Uuid;

const JWT_SECRET: &str = "integration-test-secret-with-enough-length-0123456789";

static MIGRATED: OnceCell<()> = OnceCell::const_new();

async fn setup() -> Option<(Router, PgPool)> {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("DATABASE_URL not set: skipping database integration test");
        return None;
    };
    let pool = PgPool::connect(&url)
        .await
        .expect("connect to test database");
    MIGRATED
        .get_or_init(|| async {
            sqlx::migrate!("../../migrations")
                .run(&pool)
                .await
                .expect("migrations apply cleanly");
        })
        .await;

    let (alert_tx, _) = broadcast::channel(16);
    let (traffic_tx, _) = broadcast::channel(16);
    let state = AppState {
        pool: pool.clone(),
        jwt_secret: JWT_SECRET.to_string(),
        jwt_expiration_hours: 1,
        alert_broadcast: Arc::new(alert_tx),
        traffic_broadcast: Arc::new(traffic_tx),
        rate_limiter: Arc::new(DashMap::new()),
        failed_logins: Arc::new(DashMap::new()),
        alert_dispatcher: Arc::new(AlertDispatcher::new(pool.clone(), 60)),
        redis: None,
        revoked_tokens: Arc::new(DashMap::new()),
    };
    Some((create_router(state), pool))
}

async fn token_for(pool: &PgPool, username: &str) -> String {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, role, created_at, updated_at FROM users WHERE username = $1",
    )
    .bind(username)
    .fetch_one(pool)
    .await
    .expect("seed user exists");
    backend::auth::generate_tokens(&user, JWT_SECRET, 1)
        .expect("token")
        .0
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {}", t));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn rules_crud_round_trip() {
    let Some((app, pool)) = setup().await else {
        return;
    };
    let admin = token_for(&pool, "admin").await;
    let viewer = token_for(&pool, "viewer").await;

    // Listing includes the MITRE columns (was HTTP 500: ColumnNotFound)
    let (status, body) = call(&app, "GET", "/api/rules", Some(&viewer), None).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let rules = body["data"].as_array().unwrap();
    assert!(rules.len() >= 8);
    assert!(rules.iter().any(|r| r["mitre_technique"] == "T1046"));

    let name = format!("Custom rule {}", Uuid::new_v4().simple());
    let (status, body) = call(
        &app,
        "POST",
        "/api/rules",
        Some(&admin),
        Some(json!({
            "name": name, "rule_type": "threshold", "condition_json": {"metric": "packet_rate"},
            "severity": "low", "threshold_value": 5.0, "time_window_seconds": 10,
            "mitre_tactic": "Discovery", "mitre_technique": "T1046"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let id = body["data"]["id"].as_str().unwrap().to_string();
    assert_eq!(body["data"]["mitre_tactic"], "Discovery");

    // Duplicate name -> 400 instead of 500
    let (status, _) = call(
        &app,
        "POST",
        "/api/rules",
        Some(&admin),
        Some(json!({
            "name": name, "rule_type": "threshold", "condition_json": {},
            "severity": "low", "threshold_value": 5.0, "time_window_seconds": 10
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Viewer cannot modify
    let (status, _) = call(
        &app,
        "PATCH",
        &format!("/api/rules/{}", id),
        Some(&viewer),
        Some(json!({"is_enabled": false})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Update + validation
    let (status, body) = call(
        &app,
        "PATCH",
        &format!("/api/rules/{}", id),
        Some(&admin),
        Some(json!({"threshold_value": 20.0, "is_enabled": false, "mitre_technique": ""})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert_eq!(body["data"]["threshold_value"], 20.0);
    assert_eq!(body["data"]["is_enabled"], false);
    assert!(body["data"]["mitre_technique"].is_null());
    assert_eq!(
        body["data"]["mitre_tactic"], "Discovery",
        "unspecified fields are kept"
    );

    let (status, _) = call(
        &app,
        "PATCH",
        &format!("/api/rules/{}", id),
        Some(&admin),
        Some(json!({"time_window_seconds": 0})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/api/rules/{}", id),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &app,
        "GET",
        &format!("/api/rules/{}", id),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_logs WHERE target = $1 AND action IN ('CREATE_RULE','UPDATE_RULE','DELETE_RULE')",
    )
    .bind(&name)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit, 3, "every rule change is audited");
}

#[tokio::test]
async fn alert_status_lifecycle() {
    let Some((app, pool)) = setup().await else {
        return;
    };
    let analyst = token_for(&pool, "analyst").await;
    let viewer = token_for(&pool, "viewer").await;

    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO alerts (severity, title, description, src_ip, dst_ip) VALUES ('high', 'Test alert', 'lifecycle', '10.9.8.7', '192.168.1.50') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let uri = format!("/api/alerts/{}", id);

    let (status, _) = call(
        &app,
        "PATCH",
        &uri,
        Some(&viewer),
        Some(json!({"status": "acknowledged"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = call(
        &app,
        "PATCH",
        &uri,
        Some(&analyst),
        Some(json!({"status": "acknowledged"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert!(!body["data"]["acknowledged_by"].is_null());

    // Re-opening un-assigns the incident (was: stayed locked to the analyst)
    let (status, body) = call(
        &app,
        "PATCH",
        &uri,
        Some(&analyst),
        Some(json!({"status": "open"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert!(body["data"]["acknowledged_by"].is_null());

    let (status, body) = call(
        &app,
        "PATCH",
        &uri,
        Some(&analyst),
        Some(json!({"status": "resolved"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert!(!body["data"]["resolved_at"].is_null());

    let (status, _) = call(
        &app,
        "PATCH",
        &uri,
        Some(&analyst),
        Some(json!({"status": "acknowledged"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "resolved -> acknowledged is not a valid transition"
    );

    // Invalid IP filters are rejected instead of silently returning everything
    let (status, _) = call(
        &app,
        "GET",
        "/api/alerts?src_ip=notanip",
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &app,
        "GET",
        "/api/traffic?dst_ip=999.1.1.1",
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // LIKE wildcards in search are literal
    let (status, body) = call(
        &app,
        "GET",
        "/api/alerts?search=%25%25%25&limit=200",
        Some(&viewer),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["title"].as_str().unwrap().contains('%')));

    sqlx::query("DELETE FROM alerts WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn blocklist_validation_and_expiry() {
    let Some((app, pool)) = setup().await else {
        return;
    };
    let admin = token_for(&pool, "admin").await;

    for (payload, expected) in [
        (
            json!({"ip_address": "0.0.0.0/0", "reason": "everything"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"ip_address": "127.0.0.1", "reason": "loopback"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"ip_address": "5.6.7.0/24", "reason": "huge", "duration_seconds": 9223372036854775807i64}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"ip_address": "5.6.7.8", "reason": "negative", "duration_seconds": -3600}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"ip_address": "not-an-ip", "reason": "bad"}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let (status, body) = call(
            &app,
            "POST",
            "/api/blocklist",
            Some(&admin),
            Some(payload.clone()),
        )
        .await;
        assert_eq!(status, expected, "{} -> {}", payload, body);
    }

    let (status, body) = call(
        &app,
        "POST",
        "/api/blocklist",
        Some(&admin),
        Some(json!({"ip_address": "203.0.113.77", "reason": "integration test", "duration_seconds": 3600})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    let id = body["data"]["id"].as_str().unwrap().to_string();

    // Expired entries are hidden and purged
    sqlx::query("INSERT INTO blocked_ips (ip_address, reason, blocked_until) VALUES ('203.0.113.78', 'expired', NOW() - INTERVAL '1 minute') ON CONFLICT (ip_address) DO UPDATE SET blocked_until = EXCLUDED.blocked_until")
        .execute(&pool)
        .await
        .unwrap();
    let (_, body) = call(&app, "GET", "/api/blocklist", Some(&admin), None).await;
    let ips: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["ip_address"].as_str().unwrap())
        .collect();
    assert!(ips.iter().any(|ip| ip.starts_with("203.0.113.77")));
    assert!(!ips.iter().any(|ip| ip.starts_with("203.0.113.78")));
    assert!(
        backend::handlers::blocklist::purge_expired_blocks(&pool)
            .await
            .unwrap()
            >= 1
    );

    let (status, body) = call(
        &app,
        "DELETE",
        &format!("/api/blocklist/{}", id),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"].as_str().unwrap().contains("203.0.113.77"));
    let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE action = 'UNBLOCK_IP' AND target LIKE '203.0.113.77%'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(audit >= 1, "unblock audit records the IP, not the row id");
}

#[tokio::test]
async fn notification_secrets_are_masked_for_non_admins() {
    let Some((app, pool)) = setup().await else {
        return;
    };
    let admin = token_for(&pool, "admin").await;
    let analyst = token_for(&pool, "analyst").await;

    let name = format!("Slack {}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO notification_channels (name, type, config_json, min_severity, is_enabled) VALUES ($1, 'slack', $2, 'critical', false)")
        .bind(&name)
        .bind(json!({"webhook_url": "https://hooks.slack.com/services/T0/B0/SECRETXYZ", "headers": {"Authorization": "Bearer abc"}, "options": {"api_token": "t0k"}}))
        .execute(&pool)
        .await
        .unwrap();

    let (_, body) = call(
        &app,
        "GET",
        "/api/notifications/channels",
        Some(&analyst),
        None,
    )
    .await;
    let text = body.to_string();
    assert!(!text.contains("SECRETXYZ"), "Slack webhook path leaked");
    assert!(!text.contains("Bearer abc"), "nested header leaked");
    assert!(!text.contains("t0k"), "nested token leaked");

    let (_, body) = call(
        &app,
        "GET",
        "/api/notifications/channels",
        Some(&admin),
        None,
    )
    .await;
    assert!(
        body.to_string().contains("SECRETXYZ"),
        "admins see the real config"
    );

    // Missing required config is rejected up front
    let (status, _) = call(
        &app,
        "POST",
        "/api/notifications/channels",
        Some(&admin),
        Some(
            json!({"name": "No URL", "type": "webhook", "config_json": {}, "min_severity": "high"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Test delivery failures surface the reason (not a masked 500)
    let id: Uuid = sqlx::query_scalar("INSERT INTO notification_channels (name, type, config_json, min_severity, is_enabled) VALUES ($1, 'email', $2, 'high', false) RETURNING id")
        .bind(format!("Mail {}", Uuid::new_v4().simple()))
        .bind(json!({"smtp_host": "127.0.0.1", "smtp_port": 25999, "to_email": "soc@example.com", "smtp_security": "none"}))
        .fetch_one(&pool)
        .await
        .unwrap();
    let (status, body) = call(
        &app,
        "POST",
        &format!("/api/notifications/test/{}", id),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().contains("SMTP"), "{}", body);

    sqlx::query("DELETE FROM notification_channels WHERE name = $1 OR id = $2")
        .bind(&name)
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn sensor_heartbeat_requires_token() {
    let Some((app, _pool)) = setup().await else {
        return;
    };
    let (status, _) = call(
        &app,
        "POST",
        "/api/sensor/heartbeat",
        None,
        Some(json!({"sensor_id": "fake", "sensor_version": "x", "interface_name": "eth9", "packets_captured": 1, "packets_dropped": 0})),
    )
    .await;
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
        "unauthenticated heartbeat must be rejected, got {}",
        status
    );
}

#[tokio::test]
async fn login_lockout_covers_email_login() {
    let Some((app, pool)) = setup().await else {
        return;
    };
    let username = format!("lock{}", &Uuid::new_v4().simple().to_string()[..8]);
    let email = format!("{}@example.com", username);
    let (status, _) = call(
        &app,
        "POST",
        "/api/auth/register",
        None,
        Some(json!({"username": username, "email": email, "password": "Correct-Horse-1", "role": "admin"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let role: String = sqlx::query_scalar("SELECT role::text FROM users WHERE username = $1")
        .bind(&username)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(role, "viewer", "self-registration can never pick a role");

    for _ in 0..5 {
        let (status, _) = call(
            &app,
            "POST",
            "/api/auth/login",
            None,
            Some(json!({"username": username, "password": "wrong"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    // Same account via e-mail shares the counter (was a bypass)
    let (status, _) = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({"username": email, "password": "Correct-Horse-1"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let ip: Option<String> = sqlx::query_scalar("SELECT host(ip_address) FROM audit_logs WHERE action = 'LOGIN_FAILED' AND target = $1 LIMIT 1")
        .bind(&username)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(ip.is_some(), "audit log records the client IP");

    sqlx::query("DELETE FROM users WHERE username = $1")
        .bind(&username)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn long_dns_flags_are_stored() {
    let Some((_app, pool)) = setup().await else {
        return;
    };
    let flags = format!("DNS:{}.c2.tunnel-exfil.net", "a".repeat(60));
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO traffic_events (time, id, src_ip, dst_ip, src_port, dst_port, protocol, bytes_transferred, packet_count, flags, interface_name) VALUES (NOW(), $1, '10.0.0.1', '8.8.8.8', 5000, 53, 'UDP', 100, 1, $2, 'test0')")
        .bind(id)
        .bind(&flags)
        .execute(&pool)
        .await
        .expect("long DNS flags must fit (was VARCHAR(20))");
    sqlx::query("DELETE FROM traffic_events WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn dashboard_summary_counts() {
    let Some((app, pool)) = setup().await else {
        return;
    };
    let viewer = token_for(&pool, "viewer").await;
    let (status, body) = call(&app, "GET", "/api/dashboard/summary", Some(&viewer), None).await;
    assert_eq!(status, StatusCode::OK, "{}", body);
    assert!(body["data"]["critical_alerts"].is_i64());
    assert!(
        body["data"]["total_alerts"].as_i64().unwrap()
            >= body["data"]["critical_alerts"].as_i64().unwrap()
    );
}
