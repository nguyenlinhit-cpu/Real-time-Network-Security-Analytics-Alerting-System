use chrono::Utc;
use common::models::{
    Alert, AlertSeverity, AlertStatus, DetectionRule as RuleModel, RuleType, TrafficEvent,
};
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

use super::DetectionRule;

pub struct DnsTunnelDetector {
    rule_id: Option<Uuid>,
    is_enabled: bool,
    entropy_threshold: f64,
    min_length: usize,
    last_alert_time: HashMap<String, Instant>,
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
        for ch in text.chars() {
            *counts.entry(ch).or_insert(0usize) += 1;
        }

        let len_f = text.len() as f64;
        let mut entropy = 0.0;

        for &count in counts.values() {
            let p = count as f64 / len_f;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }

        entropy
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
        // If config provides an invalid threshold (> 10.0), clamp or fallback to 3.8 (Mục 4)
        if config.threshold_value > 0.0 && config.threshold_value <= 10.0 {
            self.entropy_threshold = config.threshold_value;
        } else {
            self.entropy_threshold = 3.8;
        }
    }

    fn evaluate(&mut self, event: &TrafficEvent) -> Option<Alert> {
        if !self.is_enabled || event.dst_port != 53 {
            return None;
        }

        // Extract DNS query domain if present in flags (e.g. "DNS:xyz.tunnel.net")
        let domain_prefix = "DNS:";
        let idx = event.flags.find(domain_prefix)?;
        let start = idx + domain_prefix.len();
        let slice = &event.flags[start..];
        let domain = slice.split(',').next().unwrap_or(slice);

        let subdomain = domain.split('.').next().unwrap_or(domain);

        if subdomain.len() >= self.min_length {
            let entropy = Self::calculate_entropy(subdomain);

            if entropy >= self.entropy_threshold {
                let now = Instant::now();
                let domain_key = domain.to_string();

                if let Some(last_alert) = self.last_alert_time.get(&domain_key) {
                    if now.duration_since(*last_alert).as_secs() < 30 {
                        return None;
                    }
                }

                self.last_alert_time.insert(domain_key, now);

                return Some(Alert {
                    id: Uuid::new_v4(),
                    rule_id: self.rule_id,
                    severity: AlertSeverity::Medium,
                    title: "DNS Tunneling / Data Exfiltration Detected".to_string(),
                    description: format!(
                        "Suspicious high-entropy DNS query '{}' from {} (length: {}, entropy: {:.2}, threshold: {:.2})",
                        domain, event.src_ip, subdomain.len(), entropy, self.entropy_threshold
                    ),
                    src_ip: event.src_ip,
                    dst_ip: event.dst_ip,
                    detected_at: Utc::now(),
                    status: AlertStatus::Open,
                    acknowledged_by: None,
                    resolved_at: None,
                    mitre_tactic: Some("Exfiltration".to_string()),
                    mitre_technique: Some("T1071.004".to_string()),
                });
            }
        }

        None
    }

    fn cleanup_stale(&mut self, max_age: std::time::Duration) {
        let now = Instant::now();
        self.last_alert_time.retain(|_, t| now.duration_since(*t) < max_age);
    }
}
