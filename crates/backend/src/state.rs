use common::models::{Alert, TrafficEvent};
use dashmap::DashMap;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub jwt_secret: String,
    pub jwt_expiration_hours: i64,
    pub alert_broadcast: Arc<broadcast::Sender<Alert>>,
    pub traffic_broadcast: Arc<broadcast::Sender<TrafficEvent>>,
    pub rate_limiter: Arc<DashMap<String, (Instant, usize)>>,
    pub failed_logins: Arc<DashMap<String, (u32, Instant)>>,
    pub alert_dispatcher: Arc<crate::alerting::AlertDispatcher>,
    pub redis: Option<Arc<crate::redis_client::SimpleRedisClient>>,
}

