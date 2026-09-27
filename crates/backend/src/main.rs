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

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/network_security".to_string());
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

    // Broadcast channels for real-time WebSockets
    let (alert_broadcast_tx, _) = broadcast::channel::<Alert>(1000);
    let (traffic_broadcast_tx, _) = broadcast::channel::<TrafficEvent>(5000);

    let redis_url = std::env::var("REDIS_URL").ok();
    let redis_client = redis_url.map(|addr| {
        info!("Initializing distributed Redis cluster integration with {}", addr);
        Arc::new(backend::redis_client::SimpleRedisClient::new(Some(addr)))
    });

    let alert_dispatcher = Arc::new(backend::alerting::AlertDispatcher::with_redis(
        pool.clone(),
        60,
        redis_client.clone(),
    ));

    if jwt_secret.starts_with("super_secret") {
        tracing::warn!("⚠️ SECURITY WARNING: Using default insecure JWT_SECRET! Please set JWT_SECRET in production.");
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
    };


    let app = create_router(state);

    let addr_str = format!("{}:{}", host, port);
    let addr: SocketAddr = addr_str.parse()?;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("🚀 SecNet REST API listening on http://{}", addr);
    info!("📖 Swagger UI documentation available at http://{}/swagger-ui", addr);

    axum::serve(listener, app).await?;
    Ok(())
}
