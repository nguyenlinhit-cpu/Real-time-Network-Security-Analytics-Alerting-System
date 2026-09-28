use common::models::{Alert, TrafficBatchDto};
use dashmap::DashMap;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

use crate::middleware::rate_limit::RATE_LIMIT_WINDOW;

/// How long an account/IP pair stays locked after too many failed logins.
pub const LOCKOUT_WINDOW: Duration = Duration::from_secs(900);

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub jwt_secret: String,
    pub jwt_expiration_hours: i64,
    pub alert_broadcast: Arc<broadcast::Sender<Alert>>,
    pub traffic_broadcast: Arc<broadcast::Sender<TrafficBatchDto>>,
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
            if let Ok(true) = redis.exists(&key).await {
                return true;
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

        let expiry = Instant::now() + Duration::from_secs(ttl_seconds);
        self.revoked_tokens.insert(jti, expiry);
    }

    /// Atomically marks a refresh token as used. Returns `false` if it was already used or
    /// revoked, so two concurrent refresh requests cannot both succeed with the same token.
    pub async fn try_consume_refresh_token(&self, jti: uuid::Uuid, ttl_seconds: u64) -> bool {
        if let Some(ref redis) = self.redis {
            let key = format!("secnet:revoked:{}", jti);
            match redis.set_nx_ex(&key, "1", ttl_seconds.max(1)).await {
                Ok(acquired) => {
                    self.revoked_tokens
                        .insert(jti, Instant::now() + Duration::from_secs(ttl_seconds));
                    return acquired;
                }
                Err(e) => tracing::warn!("Redis refresh-token check failed, using memory: {}", e),
            }
        }

        let expiry = Instant::now() + Duration::from_secs(ttl_seconds);
        match self.revoked_tokens.entry(jti) {
            dashmap::mapref::entry::Entry::Occupied(mut e) => {
                if Instant::now() < *e.get() {
                    false
                } else {
                    e.insert(expiry);
                    true
                }
            }
            dashmap::mapref::entry::Entry::Vacant(e) => {
                e.insert(expiry);
                true
            }
        }
    }

    /// Drops expired entries from the in-memory security maps so they cannot grow unbounded.
    pub fn cleanup_expired_entries(&self) {
        let now = Instant::now();
        self.rate_limiter
            .retain(|_, (start, _)| now.duration_since(*start) <= RATE_LIMIT_WINDOW);
        self.failed_logins
            .retain(|_, (_, last)| now.duration_since(*last) <= LOCKOUT_WINDOW);
        self.revoked_tokens.retain(|_, expiry| now < *expiry);
    }
}
