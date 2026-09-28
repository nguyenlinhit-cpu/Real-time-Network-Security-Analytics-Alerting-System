use chrono::Utc;
use common::models::{
    Alert, AlertSeverity, AlertStatus, DetectionRule as RuleModel, RuleType, TrafficEvent,
};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::DetectionRule;

/// One alert per (client, tunnel domain) per cooldown: every tunnelled query has a fresh random
/// subdomain, so deduplicating on the full name would alert on every single packet.
const ALERT_COOLDOWN: Duration = Duration::from_secs(60);

pub struct DnsTunnelDetector {
    rule_id: Option<Uuid>,
    is_enabled: bool,
    entropy_threshold: f64,
    min_length: usize,
    last_alert_time: HashMap<(IpNetwork, String), Instant>,
}

impl DnsTunnelDetector {
    pub fn new(entropy_threshold: f64, min_length: usize) -> Self {
        Self {
            rule_id: None,
            is_enabled: true,
            entropy_threshold,
            min_length,
            last_alert_time: HashMap::new(),
        }
    }

    /// Calculate Shannon Entropy H(X) = -sum(P(x) * log2(P(x)))
    pub fn calculate_entropy(text: &str) -> f64 {
        if text.is_empty() {
            return 0.0;
        }

        let mut counts = HashMap::new();
        let mut total = 0usize;
        for ch in text.chars() {
            *counts.entry(ch).or_insert(0usize) += 1;
            total += 1;
        }

        let len_f = total as f64;
        counts
            .values()
            .map(|&count| {
                let p = count as f64 / len_f;
                -p * p.log2()
            })
            .sum()
    }

    /// Registered ("base") domain used for deduplication, e.g. `c2.tunnel-exfil.net` -> `tunnel-exfil.net`.
    fn base_domain(domain: &str) -> String {
        let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
        if labels.len() <= 2 {
            domain.to_lowercase()
        } else {
            labels[labels.len() - 2..].join(".").to_lowercase()
        }
    }

    /// The label most likely to carry encoded data: the longest one left of the base domain.
    fn payload_label(domain: &str) -> &str {
        let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
        let candidates = if labels.len() > 2 {
            &labels[..labels.len() - 2]
        } else {
            &labels[..1]
        };
        candidates
            .iter()
            .copied()
            .max_by_key(|l| l.len())
            .unwrap_or("")
    }
}

impl DetectionRule for DnsTunnelDetector {
    fn name(&self) -> &str {
        "DNS Tunneling Detection"
    }

    fn rule_type(&self) -> RuleType {
        RuleType::Anomaly
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
        // Shannon entropy of DNS label typically ranges from 1.0 to 5.5.
        // If config provides an invalid threshold (> 10.0), fall back to 3.8 (Mục 4)
        if config.threshold_value > 0.0 && config.threshold_value <= 10.0 {
            self.entropy_threshold = config.threshold_value;
        } else {
            self.entropy_threshold = 3.8;
        }
        if let Some(len) = super::condition_f64(config, "min_length") {
            self.min_length = len.clamp(8.0, 63.0) as usize;
        }
    }

    fn evaluate(&mut self, event: &TrafficEvent) -> Option<Alert> {
        if !self.is_enabled || event.dst_port != 53 {
            return None;
        }

        // Extract DNS query domain if present in flags (e.g. "DNS:xyz.tunnel.net")
        let idx = event.flags.find("DNS:")?;
        let slice = &event.flags[idx + 4..];
        let domain = slice.split(',').next().unwrap_or(slice);

        let label = Self::payload_label(domain);
        if label.chars().count() < self.min_length {
            return None;
        }

        let entropy = Self::calculate_entropy(label);
        if entropy < self.entropy_threshold {
            return None;
        }

        let now = Instant::now();
        let key = (event.src_ip, Self::base_domain(domain));
        if let Some(last_alert) = self.last_alert_time.get(&key) {
            if now.duration_since(*last_alert) < ALERT_COOLDOWN {
                return None;
            }
        }
        self.last_alert_time.insert(key.clone(), now);

        Some(Alert {
            id: Uuid::new_v4(),
            rule_id: self.rule_id,
            severity: AlertSeverity::Medium,
            title: format!("DNS Tunneling / Data Exfiltration via {}", key.1),
            description: format!(
                "Suspicious high-entropy DNS query '{}' from {} (label length: {}, entropy: {:.2}, threshold: {:.2})",
                domain,
                event.src_ip.ip(),
                label.chars().count(),
                entropy,
                self.entropy_threshold
            ),
            src_ip: event.src_ip,
            dst_ip: event.dst_ip,
            detected_at: Utc::now(),
            status: AlertStatus::Open,
            acknowledged_by: None,
            resolved_at: None,
            mitre_tactic: Some("Exfiltration".to_string()),
            mitre_technique: Some("T1071.004".to_string()),
        })
    }

    fn cleanup_stale(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.last_alert_time
            .retain(|_, t| now.duration_since(*t) < max_age.max(ALERT_COOLDOWN));
    }
}
