use chrono::Utc;
use common::models::{Alert, AlertStatus, DetectionRule as RuleModel, RuleType, TrafficEvent};
use ipnetwork::IpNetwork;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::DetectionRule;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Metric {
    PacketRate,
    ByteRate,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum GroupBy {
    SrcIp,
    DstIp,
}

/// Executes user-defined rules created from the UI. `condition_json` supports:
/// `metric` ("packet_rate" | "byte_rate"), `group_by` ("src_ip" | "dst_ip"), and optional
/// filters `protocol`, `dst_port`, `flags` (substring). The rule fires when the metric summed
/// over `time_window_seconds` for one group reaches `threshold_value`.
pub struct GenericThresholdDetector {
    config: RuleModel,
    metric: Metric,
    group_by: GroupBy,
    protocol: Option<String>,
    dst_port: Option<i32>,
    flags: Option<String>,
    window: Duration,
    history: HashMap<IpNetwork, VecDeque<(Instant, u64)>>,
    last_alert_time: HashMap<IpNetwork, Instant>,
}

impl GenericThresholdDetector {
    pub fn from_config(config: &RuleModel) -> Self {
        let mut d = Self {
            config: config.clone(),
            metric: Metric::PacketRate,
            group_by: GroupBy::SrcIp,
            protocol: None,
            dst_port: None,
            flags: None,
            window: Duration::from_secs(1),
            history: HashMap::new(),
            last_alert_time: HashMap::new(),
        };
        d.update_config(config);
        d
    }

    pub fn rule_id(&self) -> Uuid {
        self.config.id
    }

    fn matches(&self, event: &TrafficEvent) -> bool {
        if let Some(p) = &self.protocol {
            if !event.protocol.eq_ignore_ascii_case(p) {
                return false;
            }
        }
        if let Some(port) = self.dst_port {
            if event.dst_port != port {
                return false;
            }
        }
        if let Some(f) = &self.flags {
            if !event.flags.contains(f.as_str()) {
                return false;
            }
        }
        true
    }
}

impl DetectionRule for GenericThresholdDetector {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn rule_type(&self) -> RuleType {
        self.config.rule_type
    }

    fn is_enabled(&self) -> bool {
        self.config.is_enabled
    }

    fn set_enabled(&mut self, enabled: bool) {
        self.config.is_enabled = enabled;
    }

    fn update_config(&mut self, config: &RuleModel) {
        self.config = config.clone();
        let c = &config.condition_json;
        self.metric = match c.get("metric").and_then(|v| v.as_str()) {
            Some("byte_rate") | Some("bytes") => Metric::ByteRate,
            _ => Metric::PacketRate,
        };
        self.group_by = match c.get("group_by").and_then(|v| v.as_str()) {
            Some("dst_ip") => GroupBy::DstIp,
            _ => GroupBy::SrcIp,
        };
        self.protocol = c
            .get("protocol")
            .and_then(|v| v.as_str())
            .map(|s| s.to_uppercase());
        self.dst_port = c
            .get("dst_port")
            .and_then(|v| v.as_i64())
            .map(|p| p as i32);
        self.flags = c
            .get("flags")
            .and_then(|v| v.as_str())
            .map(|s| s.to_uppercase());
        self.window = Duration::from_secs(super::window_secs(config));
    }

    fn evaluate(&mut self, event: &TrafficEvent) -> Option<Alert> {
        if !self.config.is_enabled || !self.matches(event) {
            return None;
        }

        let key = match self.group_by {
            GroupBy::SrcIp => event.src_ip,
            GroupBy::DstIp => event.dst_ip,
        };
        let amount = match self.metric {
            Metric::PacketRate => event.packet_count.max(1) as u64,
            Metric::ByteRate => event.bytes_transferred.max(0) as u64,
        };

        let now = Instant::now();
        let history = self.history.entry(key).or_default();
        while let Some((t, _)) = history.front() {
            if now.duration_since(*t) > self.window {
                history.pop_front();
            } else {
                break;
            }
        }
        history.push_back((now, amount));
        let total: u64 = history.iter().map(|(_, a)| a).sum();

        if (total as f64) < self.config.threshold_value.max(1.0) {
            return None;
        }
        if let Some(last) = self.last_alert_time.get(&key) {
            if now.duration_since(*last) < self.window.max(Duration::from_secs(30)) {
                return None;
            }
        }
        self.last_alert_time.insert(key, now);

        let (metric_name, unit) = match self.metric {
            Metric::PacketRate => ("packets", "packets"),
            Metric::ByteRate => ("bytes", "bytes"),
        };

        Some(Alert {
            id: Uuid::new_v4(),
            rule_id: Some(self.config.id),
            severity: self.config.severity,
            title: format!("{} triggered for {}", self.config.name, key.ip()),
            description: format!(
                "{} {} {} within {:?} (threshold {} {}). Custom rule condition: {}",
                key.ip(),
                total,
                metric_name,
                self.window,
                self.config.threshold_value,
                unit,
                self.config.condition_json
            ),
            src_ip: event.src_ip,
            dst_ip: event.dst_ip,
            detected_at: Utc::now(),
            status: AlertStatus::Open,
            acknowledged_by: None,
            resolved_at: None,
            mitre_tactic: self.config.mitre_tactic.clone(),
            mitre_technique: self.config.mitre_technique.clone(),
        })
    }

    fn cleanup_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        let keep = max_age.max(self.window);
        self.history.retain(|_, h| {
            while let Some((t, _)) = h.front() {
                if now.duration_since(*t) > keep {
                    h.pop_front();
                } else {
                    break;
                }
            }
            !h.is_empty()
        });
        self.last_alert_time
            .retain(|_, t| now.duration_since(*t) < keep);
    }

    fn last_alert_auto_blockable(&self) -> bool {
        // Custom rules are not vetted for attribution quality; never auto-block from them.
        false
    }
}
