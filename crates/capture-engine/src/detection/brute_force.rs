use chrono::Utc;
use common::models::{
    Alert, AlertSeverity, AlertStatus, DetectionRule as RuleModel, RuleType, TrafficEvent,
};
use ipnetwork::IpNetwork;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::{threshold_count, window_secs, DetectionRule};

pub struct BruteForceDetector {
    rule_id: Option<Uuid>,
    is_enabled: bool,
    threshold_attempts: usize,
    window_duration: Duration,
    sensitive_ports: Vec<i32>,
    // (src_ip, dst_ip, port) -> timestamps of attempts
    attempt_history: HashMap<(IpNetwork, IpNetwork, i32), VecDeque<Instant>>,
    last_alert_time: HashMap<(IpNetwork, IpNetwork, i32), Instant>,
}

impl BruteForceDetector {
    pub fn new(threshold_attempts: usize, window_seconds: u64) -> Self {
        Self {
            rule_id: None,
            is_enabled: true,
            threshold_attempts,
            window_duration: Duration::from_secs(window_seconds),
            sensitive_ports: vec![21, 22, 23, 3389, 5432, 3306],
            attempt_history: HashMap::new(),
            last_alert_time: HashMap::new(),
        }
    }
}

impl DetectionRule for BruteForceDetector {
    fn name(&self) -> &str {
        "Brute-force Attack Detection"
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
        self.threshold_attempts = threshold_count(config);
        self.window_duration = Duration::from_secs(window_secs(config));
        if let Some(ports) = config
            .condition_json
            .get("dst_ports")
            .and_then(|v| v.as_array())
        {
            let parsed: Vec<i32> = ports
                .iter()
                .filter_map(|p| p.as_i64())
                .filter(|p| (1..=65535).contains(p))
                .map(|p| p as i32)
                .collect();
            if !parsed.is_empty() {
                self.sensitive_ports = parsed;
            }
        }
    }

    fn evaluate(&mut self, event: &TrafficEvent) -> Option<Alert> {
        if !self.is_enabled {
            return None;
        }

        if !self.sensitive_ports.contains(&event.dst_port) {
            return None;
        }

        // Check for connection reset/failed attempts or new connection initiations (SYN without established ACK)
        let is_failed_or_new = event.flags.contains("RST")
            || (event.flags.contains("SYN") && !event.flags.contains("ACK"));

        if !is_failed_or_new {
            return None;
        }

        let now = Instant::now();
        let key = (event.src_ip, event.dst_ip, event.dst_port);

        let history = self.attempt_history.entry(key).or_default();
        while let Some(front) = history.front() {
            if now.duration_since(*front) > self.window_duration {
                history.pop_front();
            } else {
                break;
            }
        }
        history.push_back(now);

        if history.len() >= self.threshold_attempts {
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
                title: format!(
                    "Brute-Force Authentication Attempt on Port {}",
                    event.dst_port
                ),
                description: format!(
                    "Source {} generated {} rapid connection attempts to target {}:{} within {:?}",
                    event.src_ip,
                    history.len(),
                    event.dst_ip,
                    event.dst_port,
                    self.window_duration
                ),
                src_ip: event.src_ip,
                dst_ip: event.dst_ip,
                detected_at: Utc::now(),
                status: AlertStatus::Open,
                acknowledged_by: None,
                resolved_at: None,
                mitre_tactic: Some("Credential Access".to_string()),
                mitre_technique: Some("T1110".to_string()),
            })
        } else {
            None
        }
    }

    fn cleanup_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.attempt_history.retain(|_, history| {
            while let Some(front) = history.front() {
                if now.duration_since(*front) > max_age {
                    history.pop_front();
                } else {
                    break;
                }
            }
            !history.is_empty()
        });
        self.last_alert_time
            .retain(|_, t| now.duration_since(*t) < max_age);
    }
}
