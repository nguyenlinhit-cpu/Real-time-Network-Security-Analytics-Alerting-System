use crate::redis_client::SimpleRedisClient;
use common::models::Alert;
use dashmap::{mapref::entry::Entry, DashMap};
use ipnetwork::IpNetwork;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub struct AlertThrottler {
    cache: DashMap<String, Instant>,
    window: Duration,
    redis: Option<Arc<SimpleRedisClient>>,
}

/// Deduplication key. Alerts without a rule id (rule deleted or custom) fall back to the alert
/// title, so different detectors firing for the same source IP are not merged together.
fn dedup_key(rule_id: Option<Uuid>, kind: &str, src_ip: IpNetwork) -> String {
    match rule_id {
        Some(id) => format!("{}:{}", id, src_ip),
        None => format!("title={}:{}", kind, src_ip),
    }
}

impl AlertThrottler {
    pub fn new(window_seconds: u64) -> Self {
        Self::with_redis(window_seconds, None)
    }

    pub fn with_redis(window_seconds: u64, redis: Option<Arc<SimpleRedisClient>>) -> Self {
        Self {
            cache: DashMap::new(),
            window: Duration::from_secs(window_seconds),
            redis,
        }
    }

    /// Returns true if this alert should be suppressed due to recent duplicate sending (distributed via Redis if available)
    pub async fn should_throttle_alert(&self, alert: &Alert) -> bool {
        let key = dedup_key(alert.rule_id, &alert.title, alert.src_ip);
        if let Some(ref r) = self.redis {
            match r
                .set_nx_ex(
                    &format!("secnet:throttle:{}", key),
                    "1",
                    self.window.as_secs(),
                )
                .await
            {
                // Key freshly created -> first occurrence -> do not throttle.
                Ok(acquired) => return !acquired,
                Err(e) => {
                    tracing::warn!(
                        "Redis throttle check failed, falling back to local memory: {}",
                        e
                    );
                }
            }
        }

        self.check_local(key)
    }

    /// In-memory suppression check for a rule/source pair.
    pub fn should_throttle(&self, rule_id: Option<Uuid>, src_ip: IpNetwork) -> bool {
        self.check_local(dedup_key(rule_id, "", src_ip))
    }

    fn check_local(&self, key: String) -> bool {
        let now = Instant::now();
        match self.cache.entry(key) {
            Entry::Occupied(mut e) => {
                if now.duration_since(*e.get()) < self.window {
                    true
                } else {
                    e.insert(now);
                    false
                }
            }
            Entry::Vacant(e) => {
                e.insert(now);
                false
            }
        }
    }

    /// Removes entries older than the dedup window so the cache cannot grow unbounded.
    pub fn cleanup(&self) {
        let now = Instant::now();
        self.cache
            .retain(|_, last| now.duration_since(*last) < self.window);
    }
}
