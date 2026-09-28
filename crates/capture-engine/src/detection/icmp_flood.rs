use chrono::Utc;
use common::models::{
    Alert, AlertSeverity, AlertStatus, DetectionRule as RuleModel, RuleType, TrafficEvent,
};
use ipnetwork::IpNetwork;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::DetectionRule;

/// Detector for ICMP Flood / Ping Flood / Smurf attacks
pub struct IcmpFloodDetector {
    rule_id: Option<Uuid>,
    is_enabled: bool,
    threshold_packets: usize,
    window_duration: Duration,
    // src_ip -> history of ICMP packet timestamps
    history: HashMap<IpNetwork, VecDeque<Instant>>,
    last_alert_time: HashMap<IpNetwork, Instant>,
}

impl IcmpFloodDetector {
    pub fn new(threshold_packets: usize, window_seconds: u64) -> Self {
        Self {
            rule_id: None,
            is_enabled: true,
            threshold_packets,
            window_duration: Duration::from_secs(window_seconds),
            history: HashMap::new(),
            last_alert_time: HashMap::new(),
        }
    }
}

impl DetectionRule for IcmpFloodDetector {
    fn name(&self) -> &str {
        "ICMP Flood / Smurf Attack Detection"
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
        self.window_duration = Duration::from_secs(config.time_window_seconds as u64);
    }

    fn evaluate(&mut self, event: &TrafficEvent) -> Option<Alert> {
        if !self.is_enabled {
            return None;
        }

        // Only evaluate ICMP and ICMPv6 traffic
        if event.protocol != "ICMP" && event.protocol != "ICMPv6" {
            return None;
        }

        let now = Instant::now();
        let src = event.src_ip;

        let timestamps = self.history.entry(src).or_default();

        // Prune entries outside time window
        while let Some(&oldest) = timestamps.front() {
            if now.duration_since(oldest) > self.window_duration {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        timestamps.push_back(now);

        if timestamps.len() >= self.threshold_packets {
            // Rate limit alerting per source IP (cooldown: 30 seconds)
            if let Some(last_alert) = self.last_alert_time.get(&src) {
                if now.duration_since(*last_alert) < Duration::from_secs(30) {
                    return None;
                }
            }

            self.last_alert_time.insert(src, now);

            return Some(Alert {
                id: Uuid::new_v4(),
                rule_id: self.rule_id,
                severity: AlertSeverity::High,
                title: format!("ICMP Flood / DDoS Attack from {}", src),
                description: format!(
                    "Source IP {} sent {} ICMP packets within {:?}, exceeding threshold of {} pkts. Potential DoS / Smurf attack.",
                    src,
                    timestamps.len(),
                    self.window_duration,
                    self.threshold_packets
                ),
                src_ip: src,
                dst_ip: event.dst_ip,
                detected_at: Utc::now(),
                status: AlertStatus::Open,
                acknowledged_by: None,
                resolved_at: None,
            });
        }

        None
    }

    fn cleanup_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.history.retain(|_, timestamps| {
            while let Some(&oldest) = timestamps.front() {
                if now.duration_since(oldest) > max_age {
                    timestamps.pop_front();
                } else {
                    break;
                }
            }
            !timestamps.is_empty()
        });
        self.last_alert_time.retain(|_, t| now.duration_since(*t) < max_age);
    }
}
