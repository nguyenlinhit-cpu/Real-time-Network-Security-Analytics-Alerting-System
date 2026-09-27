use crate::redis_client::SimpleRedisClient;
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub struct AlertThrottler {
    cache: DashMap<(Option<Uuid>, IpNetwork), Instant>,
    window: Duration,
    redis: Option<Arc<SimpleRedisClient>>,
}

impl AlertThrottler {
    pub fn new(window_seconds: u64) -> Self {
        Self {
            cache: DashMap::new(),
            window: Duration::from_secs(window_seconds),
            redis: None,
        }
    }

    pub fn with_redis(window_seconds: u64, redis: Option<Arc<SimpleRedisClient>>) -> Self {
        Self {
            cache: DashMap::new(),
            window: Duration::from_secs(window_seconds),
            redis,
        }
    }

    /// Returns true if this alert should be suppressed due to recent duplicate sending (distributed via Redis if available)
    pub async fn should_throttle_async(&self, rule_id: Option<Uuid>, src_ip: IpNetwork) -> bool {
        if let Some(ref r) = self.redis {
            let key = format!(
                "secnet:throttle:{}:{}",
                rule_id.map(|u| u.to_string()).unwrap_or_else(|| "none".to_string()),
                src_ip
            );
            match r.set_nx_ex(&key, "1", self.window.as_secs()).await {
                Ok(acquired) => {
                    // If acquired is true, key was freshly created -> do NOT throttle (return false)
                    // If acquired is false, key already existed -> throttle (return true)
                    return !acquired;
                }
                Err(e) => {
                    tracing::warn!("Redis throttle check failed, falling back to local memory: {}", e);
                }
            }
        }

        self.should_throttle(rule_id, src_ip)
    }

    /// In-memory suppression check
    pub fn should_throttle(&self, rule_id: Option<Uuid>, src_ip: IpNetwork) -> bool {
        let key = (rule_id, src_ip);
        let now = Instant::now();

        if let Some(mut last_seen) = self.cache.get_mut(&key) {
            if now.duration_since(*last_seen) < self.window {
                return true;
            }
            *last_seen = now;
            false
        } else {
            self.cache.insert(key, now);
            false
        }
    }
}

