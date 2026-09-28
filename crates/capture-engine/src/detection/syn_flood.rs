use chrono::Utc;
use common::models::{
    Alert, AlertSeverity, AlertStatus, DetectionRule as RuleModel, RuleType, TrafficEvent,
};
use ipnetwork::IpNetwork;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::{threshold_count, window_secs, DetectionRule};

/// A single source must account for at least this share of the SYNs to be named (and
/// auto-blocked) as the attacker. Below it the flood is distributed or spoofed.
const DOMINANT_SOURCE_SHARE: f64 = 0.5;

pub struct SynFloodDetector {
    rule_id: Option<Uuid>,
    is_enabled: bool,
    threshold_packets: usize,
    window_duration: Duration,
    // dst_ip -> (timestamp, src_ip) of SYN packets
    syn_history: HashMap<IpNetwork, VecDeque<(Instant, IpNetwork)>>,
    last_alert_time: HashMap<IpNetwork, Instant>,
    last_alert_blockable: bool,
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
            last_alert_blockable: false,
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
        self.threshold_packets = threshold_count(config);
        self.window_duration = Duration::from_secs(window_secs(config));
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

        // O(1) amortized sliding window eviction via VecDeque (Mục 31)
        let history = self.syn_history.entry(target).or_default();
        while let Some((t, _)) = history.front() {
            if now.duration_since(*t) > self.window_duration {
                history.pop_front();
            } else {
                break;
            }
        }
        history.push_back((now, event.src_ip));

        if history.len() < self.threshold_packets {
            return None;
        }

        if let Some(last_alert) = self.last_alert_time.get(&target) {
            if now.duration_since(*last_alert) < Duration::from_secs(30) {
                return None;
            }
        }

        // Attribute the flood to its dominant source rather than whoever sent the last SYN.
        let mut per_source: HashMap<IpNetwork, usize> = HashMap::new();
        for (_, src) in history.iter() {
            *per_source.entry(*src).or_default() += 1;
        }
        let total = history.len();
        let distinct_sources = per_source.len();
        let (top_src, top_count) = per_source
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .unwrap_or((event.src_ip, 0));
        let share = top_count as f64 / total as f64;
        self.last_alert_blockable = share >= DOMINANT_SOURCE_SHARE;

        self.last_alert_time.insert(target, now);

        let attribution = if self.last_alert_blockable {
            format!(
                "Dominant source {} sent {} of them ({:.0}%).",
                top_src.ip(),
                top_count,
                share * 100.0
            )
        } else {
            format!(
                "Distributed flood from {} distinct sources (largest: {} with {:.0}%); source not auto-blocked.",
                distinct_sources,
                top_src.ip(),
                share * 100.0
            )
        };

        Some(Alert {
            id: Uuid::new_v4(),
            rule_id: self.rule_id,
            severity: AlertSeverity::Critical,
            title: format!("SYN Flood / DDoS Attack Targeting {}", target.ip()),
            description: format!(
                "Target {} received {} SYN packets within {:?}, exceeding threshold of {}. {}",
                target.ip(),
                total,
                self.window_duration,
                self.threshold_packets,
                attribution
            ),
            src_ip: top_src,
            dst_ip: target,
            detected_at: Utc::now(),
            status: AlertStatus::Open,
            acknowledged_by: None,
            resolved_at: None,
            mitre_tactic: Some("Impact".to_string()),
            mitre_technique: Some("T1498".to_string()),
        })
    }

    fn cleanup_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.syn_history.retain(|_, history| {
            while let Some((t, _)) = history.front() {
                if now.duration_since(*t) > max_age {
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

    fn last_alert_auto_blockable(&self) -> bool {
        self.last_alert_blockable
    }
}
