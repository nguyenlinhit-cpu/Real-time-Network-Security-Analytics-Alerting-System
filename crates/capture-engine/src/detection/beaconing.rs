use chrono::Utc;
use common::models::{
    Alert, AlertSeverity, AlertStatus, DetectionRule as RuleModel, RuleType, TrafficEvent,
};
use ipnetwork::IpNetwork;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::DetectionRule;

/// Detector for Command & Control (C2) Periodic Beaconing Activity
/// Identifies outbound connections occurring at fixed mathematical intervals with very low jitter.
pub struct BeaconingDetector {
    rule_id: Option<Uuid>,
    is_enabled: bool,
    min_connections: usize,
    max_jitter_ratio: f64, // Coefficient of variation threshold (std_dev / mean)
    // (src_ip, dst_ip) -> history of connection timestamps
    history: HashMap<(IpNetwork, IpNetwork), VecDeque<Instant>>,
    last_alert_time: HashMap<(IpNetwork, IpNetwork), Instant>,
}

impl BeaconingDetector {
    pub fn new(min_connections: usize, max_jitter_ratio: f64) -> Self {
        Self {
            rule_id: None,
            is_enabled: true,
            min_connections,
            max_jitter_ratio,
            history: HashMap::new(),
            last_alert_time: HashMap::new(),
        }
    }

    /// Evaluates if the sequence of intervals represents periodic beaconing
    fn check_beaconing(&self, timestamps: &VecDeque<Instant>) -> Option<(f64, f64)> {
        if timestamps.len() < self.min_connections {
            return None;
        }

        // Calculate delta intervals between consecutive connections in seconds
        let mut intervals = Vec::with_capacity(timestamps.len() - 1);
        for i in 1..timestamps.len() {
            let dt = timestamps[i]
                .duration_since(timestamps[i - 1])
                .as_secs_f64();
            if dt >= 0.01 {
                intervals.push(dt);
            }
        }

        if intervals.len() < self.min_connections - 1 {
            return None;
        }

        let count = intervals.len() as f64;
        let mean_interval: f64 = intervals.iter().sum::<f64>() / count;

        // C2 beaconing typically has intervals between 0.05s and 600s
        if mean_interval < 0.05 || mean_interval > 600.0 {
            return None;
        }

        let variance: f64 = intervals
            .iter()
            .map(|&x| (x - mean_interval).powi(2))
            .sum::<f64>()
            / count;
        let std_dev = variance.sqrt();
        let cv = std_dev / mean_interval; // Coefficient of Variation (jitter ratio)

        if cv <= self.max_jitter_ratio {
            Some((mean_interval, cv))
        } else {
            None
        }
    }
}

impl DetectionRule for BeaconingDetector {
    fn name(&self) -> &str {
        "C2 Beaconing / Periodic Callback Detection"
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

        // Focus on outbound connection initiations (TCP SYN or non-service UDP packets)
        let is_syn = event.flags.contains("SYN") && !event.flags.contains("ACK");
        let is_udp = event.protocol == "UDP" && event.dst_port != 53 && event.dst_port != 123;

        if !is_syn && !is_udp {
            return None;
        }

        let key = (event.src_ip, event.dst_ip);
        let now = Instant::now();

        {
            let timestamps = self.history.entry(key).or_default();

            // Keep maximum 20 recent connections for analysis
            if timestamps.len() >= 20 {
                timestamps.pop_front();
            }
            timestamps.push_back(now);
        }

        let beacon_analysis = self
            .history
            .get(&key)
            .and_then(|ts| self.check_beaconing(ts));

        if let Some((interval, cv)) = beacon_analysis {
            if let Some(last_alert) = self.last_alert_time.get(&key) {
                if now.duration_since(*last_alert) < Duration::from_secs(60) {
                    return None;
                }
            }

            self.last_alert_time.insert(key, now);

            return Some(Alert {
                id: Uuid::new_v4(),
                rule_id: self.rule_id,
                severity: AlertSeverity::High,
                title: format!("C2 Beaconing Detected: {} -> {}", event.src_ip, event.dst_ip),
                description: format!(
                    "Suspicious periodic beaconing pattern detected from host {} to external destination {}. Mean interval: {:.2}s, Jitter: {:.1}%. Likely malware C2 channel.",
                    event.src_ip, event.dst_ip, interval, cv * 100.0
                ),
                src_ip: event.src_ip,
                dst_ip: event.dst_ip,
                detected_at: Utc::now(),
                status: AlertStatus::Open,
                acknowledged_by: None,
                resolved_at: None,
                mitre_tactic: Some("Command and Control".to_string()),
                mitre_technique: Some("T1071".to_string()),
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
        self.last_alert_time
            .retain(|_, t| now.duration_since(*t) < max_age);
    }
}
