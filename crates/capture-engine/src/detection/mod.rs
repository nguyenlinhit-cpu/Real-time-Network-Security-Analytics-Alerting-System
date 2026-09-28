pub mod arp_spoof;
pub mod beaconing;
pub mod brute_force;
pub mod dns_tunneling;
pub mod engine;
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
}
