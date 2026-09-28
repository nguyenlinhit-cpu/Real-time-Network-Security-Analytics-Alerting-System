pub mod live;
pub mod simulator;

use common::models::TrafficEvent;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub trait PacketSource: Send + Sync {
    fn next_event(&mut self) -> impl std::future::Future<Output = Option<TrafficEvent>> + Send;
}

/// Live counters reported in the sensor heartbeat.
#[derive(Debug, Default)]
pub struct SensorStats {
    /// Events handed to the detection pipeline.
    pub captured: AtomicU64,
    /// Events lost because a downstream queue was full or persistence failed.
    pub dropped: AtomicU64,
    /// Set when the capture source could not be started or died.
    pub failed: AtomicBool,
}

impl SensorStats {
    pub fn record_captured(&self) {
        self.captured.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped(&self, n: u64) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
    }

    pub fn mark_failed(&self) {
        self.failed.store(true, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (i64, i64, bool) {
        (
            self.captured.load(Ordering::Relaxed) as i64,
            self.dropped.load(Ordering::Relaxed) as i64,
            self.failed.load(Ordering::Relaxed),
        )
    }
}
