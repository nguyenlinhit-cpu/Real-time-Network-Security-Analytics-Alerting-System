use backend::{create_router, AppState};
use common::models::{Alert, TrafficBatchDto};
use dashmap::DashMap;
use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

/// Hides the password part of a connection URL before it is logged.
fn redact_url(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut u) if u.password().is_some() => {
            let _ = u.set_password(Some("****"));
            u.to_string()
        }
        Ok(u) => u.to_string(),
        Err(_) => "<invalid url>".to_string(),
    }
}

/// Subscribes to a Postgres NOTIFY channel and keeps the subscription alive across
/// connection losses (sqlx reconnects on the next `recv` after an error).
async fn listen_forever<F, Fut>(pool: PgPool, channel: &'static str, mut on_payload: F)
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut backoff = Duration::from_secs(1);
    loop {
        let mut listener = match PgListener::connect_with(&pool).await {
            Ok(l) => l,
            Err(e) => {
                error!("PgListener for '{}' failed to connect: {}", channel, e);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
                continue;
            }
        };
        if let Err(e) = listener.listen(channel).await {
            error!("Failed to LISTEN '{}': {}", channel, e);
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
            continue;
        }
        info!(
            "📡 Real-time bridge connected via PostgreSQL LISTEN '{}'",
            channel
        );
        backoff = Duration::from_secs(1);

        loop {
            match listener.recv().await {
                Ok(notification) => on_payload(notification.payload().to_string()).await,
                Err(e) => {
                    warn!(
                        "LISTEN '{}' connection lost ({}); reconnecting (notifications during the gap are lost)",
                        channel, e
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    break;
                }
            }
        }
    }
}

/// Warns loudly when the publicly documented demo passwords are still active in production.
async fn check_default_credentials(pool: &PgPool, is_prod: bool) {
    const DEFAULTS: [(&str, &str); 3] = [
        ("admin", "Admin@SecNet2026!"),
        ("analyst", "Analyst@SecNet2026!"),
        ("viewer", "Viewer@SecNet2026!"),
    ];
    for (username, password) in DEFAULTS {
        let hash: Option<String> =
            sqlx::query_scalar("SELECT password_hash FROM users WHERE username = $1")
                .bind(username)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten();
        if let Some(hash) = hash {
            if backend::auth::verify_password(password, &hash).unwrap_or(false) {
                if is_prod {
                    error!("🚨 Seed account '{}' still uses its published default password. Change it immediately!", username);
                } else {
                    warn!(
                        "Seed account '{}' uses the default demo password.",
                        username
                    );
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    backend::handlers::metrics::init_metrics();

    info!("🛡️ ========================================================");
    info!("🛡️ Starting SecNet Real-time Backend API Server");
    info!("🛡️ ========================================================");

    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://postgres:postgres@localhost:5432/network_security".to_string()
    });
    let host = std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("SERVER_PORT").unwrap_or_else(|_| "8080".to_string());
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "super_secret_jwt_key_at_least_32_bytes_long_12345".to_string());
    let jwt_expiration_hours = std::env::var("JWT_EXPIRATION_HOURS")
        .unwrap_or_else(|_| "24".to_string())
        .parse::<i64>()
        .unwrap_or(24);

    let env = std::env::var("ENVIRONMENT")
        .or_else(|_| std::env::var("APP_ENV"))
        .unwrap_or_else(|_| "development".to_string());
    let is_prod = env.eq_ignore_ascii_case("production") || env.eq_ignore_ascii_case("prod");

    if is_prod {
        let lower_secret = jwt_secret.to_lowercase();
        if lower_secret.contains("super_secret")
            || lower_secret.contains("change_in_production")
            || lower_secret.contains("default")
            || jwt_secret.len() < 32
        {
            error!("🚨 FATAL SECURITY ERROR: Server refused to start in production with missing, default, or weak JWT_SECRET! (must be >= 32 characters and not default/placeholder)");
            return Err(
                "Production requires a strong, unique JWT_SECRET with at least 32 characters"
                    .into(),
            );
        }
    } else if jwt_secret.starts_with("super_secret") || jwt_secret.contains("change_in_production")
    {
        warn!("⚠️ SECURITY WARNING: Using default insecure JWT_SECRET! Please set a unique JWT_SECRET in production.");
    }

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&database_url)
        .await?;
    info!(
        "Connected to PostgreSQL/TimescaleDB at {}",
        redact_url(&database_url)
    );

    // Migrations are the single source of schema truth; refusing to start on failure avoids
    // running against a half-migrated database (Mục 42).
    info!("📦 Checking and applying database migrations...");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .map_err(|e| {
            error!("Database migration failed: {}", e);
            e
        })?;
    info!("✅ Database migrations verified and up to date.");

    check_default_credentials(&pool, is_prod).await;

    // Broadcast channels for real-time WebSockets
    let (alert_broadcast_tx, _) = broadcast::channel::<Alert>(1000);
    let (traffic_broadcast_tx, _) = broadcast::channel::<TrafficBatchDto>(1000);

    let redis_client = std::env::var("REDIS_URL").ok().map(|addr| {
        info!(
            "Initializing distributed Redis integration with {}",
            redact_url(&addr)
        );
        Arc::new(backend::redis_client::SimpleRedisClient::new(Some(addr)))
    });

    let dedup_seconds = std::env::var("ALERT_DEDUPLICATION_WINDOW_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let alert_dispatcher = Arc::new(backend::alerting::AlertDispatcher::with_redis(
        pool.clone(),
        dedup_seconds,
        redis_client.clone(),
    ));

    // Real-time pipeline: the `alerts` INSERT trigger publishes the new alert id (Mục 1)
    {
        let alert_pool = pool.clone();
        let alert_tx = alert_broadcast_tx.clone();
        let dispatcher = alert_dispatcher.clone();
        tokio::spawn(listen_forever(pool.clone(), "new_alert", move |payload| {
            let alert_pool = alert_pool.clone();
            let alert_tx = alert_tx.clone();
            let dispatcher = dispatcher.clone();
            async move {
                let Ok(alert_id) = payload.parse::<uuid::Uuid>() else {
                    return;
                };
                let alert = sqlx::query_as::<_, Alert>(
                    "SELECT id, rule_id, severity, title, description, src_ip, dst_ip, detected_at, status, acknowledged_by, resolved_at, mitre_tactic, mitre_technique FROM alerts WHERE id = $1"
                )
                .bind(alert_id)
                .fetch_optional(&alert_pool)
                .await;

                match alert {
                    Ok(Some(alert)) => {
                        info!(
                            "🔔 [REAL-TIME PIPELINE] Alert {} ({}) -> WS + notification channels",
                            alert.id, alert.title
                        );
                        let _ = alert_tx.send(alert.clone());
                        tokio::spawn(async move {
                            if let Err(e) = dispatcher.dispatch(&alert).await {
                                warn!("Alert dispatch failed: {}", e);
                            }
                        });
                    }
                    Ok(None) => warn!("Notified alert {} not found", alert_id),
                    Err(e) => warn!("Failed to load notified alert {}: {}", alert_id, e),
                }
            }
        }));
    }

    // Real-time pipeline: batched live traffic statistics from the capture engine (Mục 2)
    {
        let traffic_tx = traffic_broadcast_tx.clone();
        tokio::spawn(listen_forever(
            pool.clone(),
            "new_traffic",
            move |payload| {
                let traffic_tx = traffic_tx.clone();
                async move {
                    match serde_json::from_str::<TrafficBatchDto>(&payload) {
                        Ok(batch) => {
                            let _ = traffic_tx.send(batch);
                        }
                        Err(e) => warn!("Ignoring malformed traffic notification: {}", e),
                    }
                }
            },
        ));
    }

    let state = AppState {
        pool: pool.clone(),
        jwt_secret,
        jwt_expiration_hours,
        alert_broadcast: Arc::new(alert_broadcast_tx),
        traffic_broadcast: Arc::new(traffic_broadcast_tx),
        rate_limiter: Arc::new(DashMap::new()),
        failed_logins: Arc::new(DashMap::new()),
        alert_dispatcher: alert_dispatcher.clone(),
        redis: redis_client,
        revoked_tokens: Arc::new(DashMap::new()),
    };

    // Housekeeping: bound in-memory maps and purge expired blocklist entries.
    {
        let state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                state.cleanup_expired_entries();
                state.alert_dispatcher.cleanup();
                match backend::handlers::blocklist::purge_expired_blocks(&state.pool).await {
                    Ok(n) if n > 0 => info!("Purged {} expired blocklist entries", n),
                    Ok(_) => {}
                    Err(e) => warn!("Blocklist purge failed: {}", e),
                }
            }
        });
    }

    let app = create_router(state);

    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("🚀 SecNet REST API listening on http://{}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
