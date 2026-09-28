pub mod arp_spoof;
pub mod beaconing;
pub mod brute_force;
pub mod dns_tunneling;
pub mod engine;
pub mod generic_threshold;
pub mod icmp_flood;
pub mod port_scan;
pub mod syn_flood;
pub mod zscore_anomaly;

use common::models::{Alert, DetectionRule as RuleModel, RuleType, TrafficEvent};

pub trait DetectionRule: Send + Sync {
    fn name(&self) -> &str;
    fn rule_type(&self) -> RuleType;
    fn is_enabled(&self) -> bool;
    fn set_enabled(&mut self, enabled: bool);
    fn update_config(&mut self, config: &RuleModel);
    fn evaluate(&mut self, event: &TrafficEvent) -> Option<Alert>;

    /// Exports internal state for persistence / snapshotting
    fn export_state(&self) -> Option<serde_json::Value> {
        None
    }

    /// Restores internal state from a persisted snapshot
    fn import_state(&mut self, _state: &serde_json::Value) {}

    /// Cleanup stale internal tracking state older than max_age
    fn cleanup_stale(&mut self, _max_age: std::time::Duration) {}

    /// Whether the source IP of the most recent alert is a trustworthy attacker attribution
    /// that may be auto-blocked. Detectors whose `src_ip` can be spoofed or names the victim
    /// (ARP spoofing, distributed floods) return false.
    fn last_alert_auto_blockable(&self) -> bool {
        true
    }
}

/// Reads a numeric field from a rule's `condition_json`.
pub(crate) fn condition_f64(config: &RuleModel, key: &str) -> Option<f64> {
    config.condition_json.get(key).and_then(|v| v.as_f64())
}

/// Positive integer threshold from the rule config (a 0 threshold would fire on every packet).
pub(crate) fn threshold_count(config: &RuleModel) -> usize {
    (config.threshold_value.max(1.0)) as usize
}

/// Rule time window, at least one second.
pub(crate) fn window_secs(config: &RuleModel) -> u64 {
    config.time_window_seconds.max(1) as u64
}
