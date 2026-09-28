use backend::{create_router, AppState};
use common::models::{Alert, TrafficEvent};
use dashmap::DashMap;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv().ok();

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

    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(&database_url)
        .await?;
    info!("Connected to PostgreSQL/TimescaleDB at {}", database_url);

    // Run database migrations automatically on startup (Mục 42)
    info!("📦 Checking and applying database migrations...");
    if let Err(e) = sqlx::migrate!("../../migrations").run(&pool).await {
        tracing::warn!("Migration notice: {}. Continuing startup.", e);
    } else {
        info!("✅ Database migrations verified and up to date.");
    }

    // Broadcast channels for real-time WebSockets
    let (alert_broadcast_tx, _) = broadcast::channel::<Alert>(1000);
    let (traffic_broadcast_tx, _) = broadcast::channel::<TrafficEvent>(5000);

    let redis_url = std::env::var("REDIS_URL").ok();
    let redis_client = redis_url.map(|addr| {
        info!(
            "Initializing distributed Redis cluster integration with {}",
            addr
        );
        Arc::new(backend::redis_client::SimpleRedisClient::new(Some(addr)))
    });

    let alert_dispatcher = Arc::new(backend::alerting::AlertDispatcher::with_redis(
        pool.clone(),
        60,
        redis_client.clone(),
    ));

    // Real-time Pipeline Connector: PostgreSQL LISTEN/NOTIFY for new alerts (Mục 1)
    let alert_pool = pool.clone();
    let alert_tx_listener = alert_broadcast_tx.clone();
    let alert_disp = alert_dispatcher.clone();
    tokio::spawn(async move {
        let mut listener = match sqlx::postgres::PgListener::connect_with(&alert_pool).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to initialize PgListener for alerts: {}", e);
                return;
            }
        };

        if let Err(e) = listener.listen("new_alert").await {
            tracing::error!("Failed to subscribe to 'new_alert' notifications: {}", e);
            return;
        }
        info!("📡 Alert real-time bridge connected via PostgreSQL LISTEN 'new_alert'");

        while let Ok(notification) = listener.recv().await {
            let payload = notification.payload();
            if let Ok(alert_id) = payload.parse::<uuid::Uuid>() {
                let alert_res = sqlx::query_as::<_, Alert>(
                    "SELECT id, rule_id, severity, title, description, src_ip, dst_ip, detected_at, status, acknowledged_by, resolved_at FROM alerts WHERE id = $1"
                )
                .bind(alert_id)
                .fetch_optional(&alert_pool)
                .await;

                if let Ok(Some(alert)) = alert_res {
                    info!("🔔 [REAL-TIME PIPELINE] Received alert {} ({}) -> Dispatching to WS and channels", alert.id, alert.title);
                    let _ = alert_tx_listener.send(alert.clone());
                    let disp = alert_disp.clone();
                    tokio::spawn(async move {
                        let _ = disp.dispatch(&alert).await;
                    });
                }
            }
        }
    });

    // Real-time Pipeline Connector: PostgreSQL LISTEN/NOTIFY for live traffic stream (Mục 2)
    let traffic_pool = pool.clone();
    let traffic_tx_listener = traffic_broadcast_tx.clone();
    tokio::spawn(async move {
        let mut listener = match sqlx::postgres::PgListener::connect_with(&traffic_pool).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to initialize PgListener for traffic: {}", e);
                return;
            }
        };

        if let Err(e) = listener.listen("new_traffic").await {
            tracing::error!("Failed to subscribe to 'new_traffic' notifications: {}", e);
            return;
        }
        info!("📡 Traffic real-time bridge connected via PostgreSQL LISTEN 'new_traffic'");

        while let Ok(notification) = listener.recv().await {
            let payload = notification.payload();
            if let Ok(event) = serde_json::from_str::<TrafficEvent>(payload) {
                let _ = traffic_tx_listener.send(event);
            }
        }
    });

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
            tracing::error!("🚨 FATAL SECURITY ERROR: Server refused to start in production with missing, default, or weak JWT_SECRET! (must be >= 32 characters and not default/placeholder)");
            panic!("Production requires a strong, unique JWT_SECRET with at least 32 characters!");
        }
    } else if jwt_secret.starts_with("super_secret") || jwt_secret.contains("change_in_production")
    {
        tracing::warn!("⚠️ SECURITY WARNING: Using default insecure JWT_SECRET! Please set a unique JWT_SECRET in production.");
    }

    let state = AppState {
        pool,
        jwt_secret,
        jwt_expiration_hours,
        alert_broadcast: Arc::new(alert_broadcast_tx),
        traffic_broadcast: Arc::new(traffic_broadcast_tx),
        rate_limiter: Arc::new(DashMap::new()),
        failed_logins: Arc::new(DashMap::new()),
        alert_dispatcher,
        redis: redis_client,
        revoked_tokens: Arc::new(DashMap::new()),
    };

    let app = create_router(state);

    let addr_str = format!("{}:{}", host, port);
    let addr: SocketAddr = addr_str.parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("🚀 SecNet REST API listening on http://{}", addr);
    info!(
        "📖 Swagger UI documentation available at http://{}/swagger-ui",
        addr
    );

    axum::serve(listener, app).await?;
    Ok(())
}
