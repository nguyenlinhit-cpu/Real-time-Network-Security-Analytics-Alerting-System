use chrono::Utc;
use common::models::{
    Alert, AlertSeverity, AlertStatus, DetectionRule as RuleModel, RuleType, TrafficEvent,
};
use ipnetwork::IpNetwork;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::DetectionRule;

const STATE_VERSION: u64 = 2;
/// Minimum number of completed 1-second buckets before scoring starts.
const MIN_BASELINE_BUCKETS: usize = 10;
const ALERT_COOLDOWN: Duration = Duration::from_secs(30);

/// Traffic volume anomaly detector: aggregates bytes per 1-second bucket (by packet capture
/// time) and flags buckets whose volume is `z_threshold` standard deviations above both a
/// sliding-window baseline and an EWMA baseline.
pub struct ZScoreAnomalyDetector {
    rule_id: Option<Uuid>,
    is_enabled: bool,
    z_threshold: f64,
    /// Number of 1-second buckets kept as the sliding-window baseline.
    window_size: usize,
    history: VecDeque<f64>,
    last_alert_time: Option<Instant>,
    ewma_alpha: f64,
    ewma_mean: Option<f64>,
    ewma_variance: Option<f64>,
    // Bucket currently being filled
    bucket_second: Option<i64>,
    bucket_bytes: f64,
    bucket_flows: HashMap<(IpNetwork, IpNetwork), i64>,
}

impl ZScoreAnomalyDetector {
    pub fn new(z_threshold: f64, window_size: usize) -> Self {
        Self::with_ewma(z_threshold, window_size, 0.05)
    }

    pub fn with_ewma(z_threshold: f64, window_size: usize, ewma_alpha: f64) -> Self {
        Self {
            rule_id: None,
            is_enabled: true,
            z_threshold,
            window_size: window_size.max(MIN_BASELINE_BUCKETS),
            history: VecDeque::with_capacity(window_size),
            last_alert_time: None,
            ewma_alpha: ewma_alpha.clamp(0.01, 0.5),
            ewma_mean: None,
            ewma_variance: None,
            bucket_second: None,
            bucket_bytes: 0.0,
            bucket_flows: HashMap::new(),
        }
    }

    /// Scores `value` against the baselines built from *previous* buckets only, so a spike
    /// cannot dilute its own baseline.
    fn score(&self, value: f64) -> Option<(f64, f64)> {
        if self.history.len() < MIN_BASELINE_BUCKETS {
            return None;
        }
        let n = self.history.len() as f64;
        let mean = self.history.iter().sum::<f64>() / n;
        let variance = self.history.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / n;
        // Floor the deviation at 5% of the mean so near-constant traffic does not turn tiny
        // fluctuations into huge z-scores.
        let std_dev = variance.sqrt().max(mean * 0.05).max(1.0);
        let window_z = (value - mean) / std_dev;

        let ewma_z = match (self.ewma_mean, self.ewma_variance) {
            (Some(m), Some(v)) => (value - m) / v.sqrt().max(m * 0.05).max(1.0),
            _ => window_z,
        };
        // Both baselines must agree that this is a spike.
        Some((window_z.min(ewma_z), mean))
    }

    fn learn(&mut self, value: f64) {
        match (self.ewma_mean, self.ewma_variance) {
            (Some(mean), Some(var)) => {
                let diff = value - mean;
                self.ewma_mean = Some(mean + self.ewma_alpha * diff);
                self.ewma_variance =
                    Some((1.0 - self.ewma_alpha) * (var + self.ewma_alpha * diff * diff));
            }
            _ => {
                self.ewma_mean = Some(value);
                self.ewma_variance = Some(0.0);
            }
        }
        if self.history.len() >= self.window_size {
            self.history.pop_front();
        }
        self.history.push_back(value);
    }

    /// Closes the current bucket, returning an alert if it was anomalous.
    fn close_bucket(&mut self) -> Option<Alert> {
        let value = self.bucket_bytes;
        let flows = std::mem::take(&mut self.bucket_flows);
        self.bucket_bytes = 0.0;

        let scored = self.score(value);
        self.learn(value);
        let (z_score, baseline) = scored?;
        if z_score < self.z_threshold {
            return None;
        }

        let now = Instant::now();
        if let Some(last) = self.last_alert_time {
            if now.duration_since(last) < ALERT_COOLDOWN {
                return None;
            }
        }
        self.last_alert_time = Some(now);

        let ((src, dst), top_bytes) = flows.into_iter().max_by_key(|(_, b)| *b)?;

        Some(Alert {
            id: Uuid::new_v4(),
            rule_id: self.rule_id,
            severity: AlertSeverity::Medium,
            title: "Traffic Volume Spike Anomaly Detected".to_string(),
            description: format!(
                "Traffic volume of {:.0} bytes/s vs. baseline {:.0} bytes/s (Z-Score: {:.2}, threshold: {:.2}). Top flow {} -> {} carried {} bytes.",
                value,
                baseline,
                z_score,
                self.z_threshold,
                src.ip(),
                dst.ip(),
                top_bytes
            ),
            src_ip: src,
            dst_ip: dst,
            detected_at: Utc::now(),
            status: AlertStatus::Open,
            acknowledged_by: None,
            resolved_at: None,
            mitre_tactic: Some("Exfiltration".to_string()),
            mitre_technique: Some("T1020".to_string()),
        })
    }
}

impl DetectionRule for ZScoreAnomalyDetector {
    fn name(&self) -> &str {
        "Traffic Volume Anomaly (Z-Score)"
    }

    fn rule_type(&self) -> RuleType {
        RuleType::Anomaly
    }

    fn is_enabled(&self) -> bool {
        self.is_enabled
    }

    fn set_enabled(&mut self, enabled: bool) {
        self.is_enabled = enabled;
    }

    fn update_config(&mut self, config: &RuleModel) {
        self.rule_id = Some(config.id);
        self.is_enabled = config.is_enabled;
        if config.threshold_value > 0.0 {
            self.z_threshold = config.threshold_value;
        }
        // time_window_seconds = baseline length in seconds (one bucket per second).
        self.window_size = (config.time_window_seconds.max(MIN_BASELINE_BUCKETS as i32)) as usize;
        while self.history.len() > self.window_size {
            self.history.pop_front();
        }
    }

    fn evaluate(&mut self, event: &TrafficEvent) -> Option<Alert> {
        if !self.is_enabled {
            return None;
        }

        let second = event.time.timestamp();
        let mut alert = None;
        match self.bucket_second {
            Some(current) if second > current => {
                alert = self.close_bucket();
                // Idle seconds are real zero-volume samples for the baseline.
                let idle = ((second - current - 1).max(0) as usize).min(self.window_size);
                for _ in 0..idle {
                    self.learn(0.0);
                }
                self.bucket_second = Some(second);
            }
            None => self.bucket_second = Some(second),
            // Same bucket, or a slightly out-of-order packet: count it in the open bucket.
            _ => {}
        }

        self.bucket_bytes += event.bytes_transferred.max(0) as f64;
        *self
            .bucket_flows
            .entry((event.src_ip, event.dst_ip))
            .or_default() += event.bytes_transferred.max(0);

        alert
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let history_vec: Vec<f64> = self.history.iter().copied().collect();
        Some(serde_json::json!({
            "version": STATE_VERSION,
            "history": history_vec,
            "ewma_mean": self.ewma_mean,
            "ewma_variance": self.ewma_variance,
        }))
    }

    fn import_state(&mut self, state: &serde_json::Value) {
        // Version 1 stored per-packet sizes, which are not comparable to per-second volumes.
        if state.get("version").and_then(|v| v.as_u64()) != Some(STATE_VERSION) {
            return;
        }
        if let Some(arr) = state.get("history").and_then(|v| v.as_array()) {
            self.history = arr
                .iter()
                .filter_map(|v| v.as_f64())
                .take(self.window_size)
                .collect();
        }
        self.ewma_mean = state.get("ewma_mean").and_then(|v| v.as_f64());
        self.ewma_variance = state.get("ewma_variance").and_then(|v| v.as_f64());
    }
}
