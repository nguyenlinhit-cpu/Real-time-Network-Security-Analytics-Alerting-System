use chrono::Utc;
use common::models::{
    Alert, AlertSeverity, AlertStatus, DetectionRule as RuleModel, RuleType, TrafficEvent,
};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::DetectionRule;

/// If the trusted MAC of an IP has not been seen for this long, a new MAC is accepted as a
/// legitimate hardware/DHCP change instead of being reported forever.
const DEFAULT_RELEARN_AFTER: Duration = Duration::from_secs(3600);
const ALERT_COOLDOWN: Duration = Duration::from_secs(30);
const STATE_VERSION: u64 = 2;

struct MacBinding {
    mac: String,
    last_seen: Instant,
}

/// Detects ARP cache poisoning: an ARP packet whose *sender* IP claims a MAC address different
/// from the one previously learned for that IP.
pub struct ArpSpoofDetector {
    rule_id: Option<Uuid>,
    is_enabled: bool,
    relearn_after: Duration,
    // sender IP -> trusted MAC binding
    ip_to_mac: HashMap<IpNetwork, MacBinding>,
    last_alert_time: HashMap<IpNetwork, Instant>,
}

impl ArpSpoofDetector {
    pub fn new() -> Self {
        Self {
            rule_id: None,
            is_enabled: true,
            relearn_after: DEFAULT_RELEARN_AFTER,
            ip_to_mac: HashMap::new(),
            last_alert_time: HashMap::new(),
        }
    }

    fn parse_mac(flags: &str) -> Option<String> {
        let idx = flags.find("MAC:")?;
        let slice = &flags[idx + 4..];
        let mac = slice.split(',').next().unwrap_or(slice).trim().to_lowercase();
        (!mac.is_empty()).then_some(mac)
    }
}

impl Default for ArpSpoofDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionRule for ArpSpoofDetector {
    fn name(&self) -> &str {
        "ARP Spoofing / Poisoning Detection"
    }

    fn rule_type(&self) -> RuleType {
        RuleType::Pattern
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
        if let Some(secs) = super::condition_f64(config, "relearn_after_seconds") {
            self.relearn_after = Duration::from_secs(secs.max(60.0) as u64);
        }
    }

    fn evaluate(&mut self, event: &TrafficEvent) -> Option<Alert> {
        if !self.is_enabled || event.protocol != "ARP" {
            return None;
        }

        let mac = Self::parse_mac(&event.flags)?;
        // The binding under attack is the one the packet *claims*: sender IP -> sender MAC.
        let claimed_ip = event.src_ip;
        // ARP probes (sender 0.0.0.0) carry no binding.
        if claimed_ip.ip().is_unspecified() {
            return None;
        }

        let now = Instant::now();
        let binding = match self.ip_to_mac.get_mut(&claimed_ip) {
            None => {
                self.ip_to_mac.insert(
                    claimed_ip,
                    MacBinding {
                        mac,
                        last_seen: now,
                    },
                );
                return None;
            }
            Some(b) => b,
        };

        if binding.mac == mac {
            binding.last_seen = now;
            return None;
        }

        if now.duration_since(binding.last_seen) > self.relearn_after {
            tracing::info!(
                "ARP binding for {} changed {} -> {} after long inactivity; re-learning",
                claimed_ip.ip(),
                binding.mac,
                mac
            );
            binding.mac = mac;
            binding.last_seen = now;
            return None;
        }

        // Keep the trusted MAC (no flapping) and report the conflicting one.
        let trusted_mac = binding.mac.clone();
        if let Some(last_alert) = self.last_alert_time.get(&claimed_ip) {
            if now.duration_since(*last_alert) < ALERT_COOLDOWN {
                return None;
            }
        }
        self.last_alert_time.insert(claimed_ip, now);

        Some(Alert {
            id: Uuid::new_v4(),
            rule_id: self.rule_id,
            severity: AlertSeverity::Critical,
            title: format!("ARP Spoofing Detected on IP {}", claimed_ip.ip()),
            description: format!(
                "ARP packet claims {} is at {}, but the trusted MAC is {}. Possible MITM / ARP poisoning by host with MAC {} (target {}).",
                claimed_ip.ip(),
                mac,
                trusted_mac,
                mac,
                event.dst_ip.ip()
            ),
            src_ip: claimed_ip,
            dst_ip: event.dst_ip,
            detected_at: Utc::now(),
            status: AlertStatus::Open,
            acknowledged_by: None,
            resolved_at: None,
            mitre_tactic: Some("Credential Access".to_string()),
            mitre_technique: Some("T1557".to_string()),
        })
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let bindings: HashMap<String, String> = self
            .ip_to_mac
            .iter()
            .map(|(ip, b)| (ip.to_string(), b.mac.clone()))
            .collect();
        Some(serde_json::json!({ "version": STATE_VERSION, "bindings": bindings }))
    }

    fn import_state(&mut self, state: &serde_json::Value) {
        // Older snapshots keyed bindings by the ARP *target* IP and may hold poisoned entries,
        // so only the current format is restored.
        if state.get("version").and_then(|v| v.as_u64()) != Some(STATE_VERSION) {
            tracing::info!("Ignoring ARP state snapshot from an older format");
            return;
        }
        if let Some(map) = state.get("bindings").and_then(|v| v.as_object()) {
            let now = Instant::now();
            for (ip_str, mac_val) in map {
                if let (Ok(ip), Some(mac)) = (ip_str.parse::<IpNetwork>(), mac_val.as_str()) {
                    self.ip_to_mac.insert(
                        ip,
                        MacBinding {
                            mac: mac.to_string(),
                            last_seen: now,
                        },
                    );
                }
            }
        }
    }

    fn cleanup_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.last_alert_time
            .retain(|_, t| now.duration_since(*t) < max_age);
        // Bindings are bounded by the LAN size; only forget ones idle far beyond re-learn time.
        let forget_after = self.relearn_after * 24;
        self.ip_to_mac
            .retain(|_, b| now.duration_since(b.last_seen) < forget_after);
    }

    fn last_alert_auto_blockable(&self) -> bool {
        // The claimed IP is the victim, not the attacker.
        false
    }
}
