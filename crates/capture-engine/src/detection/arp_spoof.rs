use chrono::Utc;
use common::models::{
    Alert, AlertSeverity, AlertStatus, DetectionRule as RuleModel, RuleType, TrafficEvent,
};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

use super::DetectionRule;

pub struct ArpSpoofDetector {
    rule_id: Option<Uuid>,
    is_enabled: bool,
    // ip_address -> last observed MAC address
    ip_to_mac: HashMap<IpNetwork, String>,
    last_alert_time: HashMap<IpNetwork, Instant>,
}

impl ArpSpoofDetector {
    pub fn new() -> Self {
        Self {
            rule_id: None,
            is_enabled: true,
            ip_to_mac: HashMap::new(),
            last_alert_time: HashMap::new(),
        }
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
    }

    fn evaluate(&mut self, event: &TrafficEvent) -> Option<Alert> {
        if !self.is_enabled {
            return None;
        }

        // Check if event carries MAC address information (e.g. in flags "MAC:xx:xx:xx:xx:xx:xx")
        let mac_prefix = "MAC:";
        let idx = event.flags.find(mac_prefix)?;
        let start = idx + mac_prefix.len();
        let slice = &event.flags[start..];
        let mac = slice.split(',').next().unwrap_or(slice).to_lowercase();

        let target_ip = event.dst_ip;

        if let Some(existing_mac) = self.ip_to_mac.get(&target_ip) {
            if existing_mac != &mac {
                let now = Instant::now();
                if let Some(last_alert) = self.last_alert_time.get(&target_ip) {
                    if now.duration_since(*last_alert).as_secs() < 30 {
                        return None;
                    }
                }

                self.last_alert_time.insert(target_ip, now);
                let old_mac = existing_mac.clone();
                self.ip_to_mac.insert(target_ip, mac.clone());

                return Some(Alert {
                    id: Uuid::new_v4(),
                    rule_id: self.rule_id,
                    severity: AlertSeverity::Critical,
                    title: format!("ARP Spoofing Detected on IP {}", target_ip),
                    description: format!(
                        "IP {} changed MAC address unexpectedly from {} to {}. Possible MITM / ARP Poisoning attack.",
                        target_ip, old_mac, mac
                    ),
                    src_ip: event.src_ip,
                    dst_ip: target_ip,
                    detected_at: Utc::now(),
                    status: AlertStatus::Open,
                    acknowledged_by: None,
                    resolved_at: None,
                });
            }
        } else {
            self.ip_to_mac.insert(target_ip, mac);
        }

        None
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let map: HashMap<String, String> = self
            .ip_to_mac
            .iter()
            .map(|(ip, mac)| (ip.to_string(), mac.clone()))
            .collect();
        serde_json::to_value(map).ok()
    }

    fn import_state(&mut self, state: &serde_json::Value) {
        if let Some(map) = state.as_object() {
            for (ip_str, mac_val) in map {
                if let (Ok(ip), Some(mac)) = (ip_str.parse::<IpNetwork>(), mac_val.as_str()) {
                    self.ip_to_mac.insert(ip, mac.to_string());
                }
            }
        }
    }
}
