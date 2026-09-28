use chrono::Utc;
use common::models::{
    Alert, AlertSeverity, AlertStatus, DetectionRule as RuleModel, RuleType, TrafficEvent,
};
use ipnetwork::IpNetwork;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::DetectionRule;

pub struct PortScanDetector {
    rule_id: Option<Uuid>,
    is_enabled: bool,
    threshold_ports: usize,
    window_duration: Duration,
    // (src_ip, dst_ip) -> list of (timestamp, dst_port)
    connection_history: HashMap<(IpNetwork, IpNetwork), VecDeque<(Instant, u16)>>,
    last_alert_time: HashMap<(IpNetwork, IpNetwork), Instant>,
}

impl PortScanDetector {
    pub fn new(threshold_ports: usize, window_seconds: u64) -> Self {
        Self {
            rule_id: None,
            is_enabled: true,
            threshold_ports,
            window_duration: Duration::from_secs(window_seconds),
            connection_history: HashMap::new(),
            last_alert_time: HashMap::new(),
        }
    }
}

impl DetectionRule for PortScanDetector {
    fn name(&self) -> &str {
        "Port Scan Detection"
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
        self.threshold_ports = config.threshold_value as usize;
        self.window_duration = Duration::from_secs(config.time_window_seconds.max(1) as u64);
    }

    fn evaluate(&mut self, event: &TrafficEvent) -> Option<Alert> {
        if !self.is_enabled || event.dst_port <= 0 {
            return None;
        }

        // For TCP, only consider connection initiations (SYN without ACK), avoiding server responses on ephemeral ports (Mục 25)
        if event.protocol == "TCP" && (!event.flags.contains("SYN") || event.flags.contains("ACK")) {
            return None;
        }

        let now = Instant::now();
        let key = (event.src_ip, event.dst_ip);
        let dst_port = event.dst_port as u16;

        let history = self.connection_history.entry(key).or_default();
        while let Some((t, _)) = history.front() {
            if now.duration_since(*t) > self.window_duration {
                history.pop_front();
            } else {
                break;
            }
        }
        history.push_back((now, dst_port));

        let distinct_ports: HashSet<u16> = history.iter().map(|(_, p)| *p).collect();

        if distinct_ports.len() >= self.threshold_ports {
            // Check alert throttling (1 alert per 30 seconds per source/target pair)
            if let Some(last_alert) = self.last_alert_time.get(&key) {
                if now.duration_since(*last_alert) < Duration::from_secs(30) {
                    return None;
                }
            }

            self.last_alert_time.insert(key, now);

            Some(Alert {
                id: Uuid::new_v4(),
                rule_id: self.rule_id,
                severity: AlertSeverity::High,
                title: format!("Port Scan Attack Detected from {}", event.src_ip),
                description: format!(
                    "Source IP {} connected to {} distinct ports on destination {} within {:?}",
                    event.src_ip,
                    distinct_ports.len(),
                    event.dst_ip,
                    self.window_duration
                ),
                src_ip: event.src_ip,
                dst_ip: event.dst_ip,
                detected_at: Utc::now(),
                status: AlertStatus::Open,
                acknowledged_by: None,
                resolved_at: None,
                mitre_tactic: Some("Discovery".to_string()),
                mitre_technique: Some("T1046".to_string()),
            })
        } else {
            None
        }
    }

    fn cleanup_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.connection_history.retain(|_, history| {
            while let Some((t, _)) = history.front() {
                if now.duration_since(*t) > max_age {
                    history.pop_front();
                } else {
                    break;
                }
            }
            !history.is_empty()
        });
        self.last_alert_time.retain(|_, t| now.duration_since(*t) < max_age);
    }
}
