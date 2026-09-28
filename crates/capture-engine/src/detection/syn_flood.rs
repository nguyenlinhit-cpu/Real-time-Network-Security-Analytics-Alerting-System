use chrono::Utc;
use common::models::{
    Alert, AlertSeverity, AlertStatus, DetectionRule as RuleModel, RuleType, TrafficEvent,
};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::DetectionRule;

pub struct SynFloodDetector {
    rule_id: Option<Uuid>,
    is_enabled: bool,
    threshold_packets: usize,
    window_duration: Duration,
    // dst_ip -> timestamps of SYN packets
    syn_history: HashMap<IpNetwork, Vec<Instant>>,
    last_alert_time: HashMap<IpNetwork, Instant>,
}

impl SynFloodDetector {
    pub fn new(threshold_packets: usize, window_seconds: u64) -> Self {
        Self {
            rule_id: None,
            is_enabled: true,
            threshold_packets,
            window_duration: Duration::from_secs(window_seconds),
            syn_history: HashMap::new(),
            last_alert_time: HashMap::new(),
        }
    }
}

impl DetectionRule for SynFloodDetector {
    fn name(&self) -> &str {
        "SYN Flood / DDoS Detection"
    }

    fn rule_type(&self) -> RuleType {
        RuleType::Threshold
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
        self.threshold_packets = config.threshold_value as usize;
        self.window_duration = Duration::from_secs(config.time_window_seconds.max(1) as u64);
    }

    fn evaluate(&mut self, event: &TrafficEvent) -> Option<Alert> {
        if !self.is_enabled {
            return None;
        }

        // Only process TCP SYN packets without ACK
        let is_syn_only =
            event.protocol == "TCP" && event.flags.contains("SYN") && !event.flags.contains("ACK");

        if !is_syn_only {
            return None;
        }

        let now = Instant::now();
        let target = event.dst_ip;

        let history = self.syn_history.entry(target).or_default();
        history.retain(|t| now.duration_since(*t) <= self.window_duration);
        history.push(now);

        if history.len() >= self.threshold_packets {
            if let Some(last_alert) = self.last_alert_time.get(&target) {
                if now.duration_since(*last_alert) < Duration::from_secs(30) {
                    return None;
                }
            }

            self.last_alert_time.insert(target, now);

            Some(Alert {
                id: Uuid::new_v4(),
                rule_id: self.rule_id,
                severity: AlertSeverity::Critical,
                title: format!("SYN Flood / DDoS Attack Targeting {}", target),
                description: format!(
                    "Target {} received {} SYN packets within {:?}, exceeding threshold of {}",
                    target,
                    history.len(),
                    self.window_duration,
                    self.threshold_packets
                ),
                src_ip: event.src_ip,
                dst_ip: event.dst_ip,
                detected_at: Utc::now(),
                status: AlertStatus::Open,
                acknowledged_by: None,
                resolved_at: None,
            })
        } else {
            None
        }
    }
}
