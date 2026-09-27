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
    pub revoked_tokens: Arc<DashMap<uuid::Uuid, Instant>>,
}

impl AppState {
    /// Checks if a JWT token has been revoked / logged out (via Redis cluster or local memory)
    pub async fn is_token_revoked(&self, jti: uuid::Uuid) -> bool {
        if let Some(ref redis) = self.redis {
            let key = format!("secnet:revoked:{}", jti);
            if let Ok(exists) = redis.exists(&key).await {
                if exists {
                    return true;
                }
            }
        }

        if let Some(expiry) = self.revoked_tokens.get(&jti) {
            if Instant::now() < *expiry {
                return true;
            }
        }

        false
    }

    /// Revokes a JWT token (logs out session across all instances)
    pub async fn revoke_token(&self, jti: uuid::Uuid, ttl_seconds: u64) {
        if let Some(ref redis) = self.redis {
            let key = format!("secnet:revoked:{}", jti);
            let _ = redis.set_ex(&key, "1", ttl_seconds).await;
        }

        let expiry = Instant::now() + std::time::Duration::from_secs(ttl_seconds);
        self.revoked_tokens.insert(jti, expiry);
    }
}


