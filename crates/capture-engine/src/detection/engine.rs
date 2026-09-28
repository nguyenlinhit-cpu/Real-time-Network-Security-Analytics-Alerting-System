use common::models::{Alert, AlertSeverity, DetectionRule as RuleModel, TrafficEvent};
use ipnetwork::IpNetwork;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, info, warn};

use super::arp_spoof::ArpSpoofDetector;
use super::beaconing::BeaconingDetector;
use super::brute_force::BruteForceDetector;
use super::dns_tunneling::DnsTunnelDetector;
use super::icmp_flood::IcmpFloodDetector;
use super::port_scan::PortScanDetector;
use super::syn_flood::SynFloodDetector;
use super::zscore_anomaly::ZScoreAnomalyDetector;
use super::DetectionRule;

pub struct DetectionEngine {
    rules: Vec<Box<dyn DetectionRule>>,
    alert_tx: Sender<Alert>,
}

impl DetectionEngine {
    pub fn new(alert_tx: Sender<Alert>) -> Self {
        let rules: Vec<Box<dyn DetectionRule>> = vec![
            Box::new(PortScanDetector::new(15, 10)),
            Box::new(SynFloodDetector::new(200, 5)),
            Box::new(BruteForceDetector::new(5, 30)),
            Box::new(ArpSpoofDetector::new()),
            Box::new(DnsTunnelDetector::new(3.8, 30)),
            Box::new(ZScoreAnomalyDetector::new(3.0, 100)),
            Box::new(IcmpFloodDetector::new(50, 5)),
            Box::new(BeaconingDetector::new(6, 0.15)),
        ];

        Self { rules, alert_tx }
    }

    /// Snapshot all rules state to JSON
    pub fn snapshot_state(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for rule in &self.rules {
            if let Some(state) = rule.export_state() {
                map.insert(rule.name().to_string(), state);
            }
        }
        serde_json::Value::Object(map)
    }

    /// Restore all rules state from JSON
    pub fn restore_state(&mut self, state: &serde_json::Value) {
        if let Some(obj) = state.as_object() {
            for rule in &mut self.rules {
                if let Some(rule_state) = obj.get(rule.name()) {
                    rule.import_state(rule_state);
                    info!("Restored persisted state for rule: {}", rule.name());
                }
            }
        }
    }

    /// Save state to file atomically using temporary file
    pub fn save_state_to_file(&self, path: &str) -> Result<(), std::io::Error> {
        let json = self.snapshot_state();
        let content = serde_json::to_string_pretty(&json)?;
        let tmp_path = format!("{}.tmp", path);
        std::fs::write(&tmp_path, content)?;
        std::fs::rename(&tmp_path, path)?;
        info!("Saved rule state snapshot atomically to {}", path);
        Ok(())
    }

    /// Load state from file
    pub fn load_state_from_file(&mut self, path: &str) -> Result<(), std::io::Error> {
        if std::path::Path::new(path).exists() {
            let content = std::fs::read_to_string(path)?;
            if let Ok(json) = serde_json::from_str(&content) {
                self.restore_state(&json);
                info!("Loaded rule state snapshot from {}", path);
            }
        }
        Ok(())
    }

    /// Update detection rules dynamically from database configuration
    pub async fn reload_rules_from_db(&mut self, pool: &PgPool) -> Result<(), sqlx::Error> {
        let db_rules = sqlx::query_as::<_, RuleModel>(
            "SELECT id, name, rule_type, condition_json, severity, is_enabled, threshold_value, time_window_seconds, created_at, updated_at FROM detection_rules"
        )
        .fetch_all(pool)
        .await?;

        for db_rule in db_rules {
            for rule in &mut self.rules {
                let matches = rule.name() == db_rule.name
                    || (rule.name() == "Brute-force Attack Detection"
                        && db_rule.name == "SSH/RDP Brute-Force Detection")
                    || (rule.name() == "ARP Spoofing / Poisoning Detection"
                        && db_rule.name == "ARP Spoofing Detection");
                if matches {
                    rule.update_config(&db_rule);
                    info!("Updated configuration for rule: {}", rule.name());
                }
            }
        }

        Ok(())
    }

    /// Process a single event through all detection rules
    pub async fn process_event(&mut self, event: &TrafficEvent) {
        for rule in &mut self.rules {
            if let Some(alert) = rule.evaluate(event) {
                info!(
                    "🚨 [ALERT TRIGGERED] {} - {}",
                    alert.title, alert.description
                );
                if let Err(e) = self.alert_tx.send(alert).await {
                    error!("Failed to forward alert to alerting channel: {}", e);
                }
            }
        }
    }

    /// Process a batch of events (optimized for high-throughput pipeline > 10,000 pkts/sec)
    pub async fn process_batch(&mut self, events: &[TrafficEvent]) {
        for event in events {
            for rule in &mut self.rules {
                if let Some(alert) = rule.evaluate(event) {
                    info!(
                        "🚨 [ALERT TRIGGERED] {} - {}",
                        alert.title, alert.description
                    );
                    if let Err(e) = self.alert_tx.send(alert).await {
                        error!("Failed to forward alert to alerting channel: {}", e);
                    }
                }
            }
        }
    }
}

/// Check if an IP address belongs to the infrastructure allowlist (Mục 17)
pub fn is_allowlisted_ip(ip: &IpNetwork) -> bool {
    let ip_addr = ip.ip();
    if ip_addr.is_loopback() {
        return true;
    }
    let ip_str = ip_addr.to_string();
    if ip_str == "192.168.1.1" || ip_str == "8.8.8.8" || ip_str == "1.1.1.1" {
        return true;
    }
    if let Ok(allowlist) = std::env::var("ALLOWLIST_IPS") {
        for allowed in allowlist.split(',') {
            if allowed.trim() == ip_str {
                return true;
            }
        }
    }
    false
}

/// Helper to trigger active OS firewall blocking (iptables / nftables)
pub async fn apply_os_firewall_block(ip: IpNetwork) {
    let ip_str = ip.ip().to_string();
    info!(
        "🛡️ [AUTO-RESPONSE FIREWALL] Auto-blocking malicious IP {} via OS firewall",
        ip_str
    );

    // 1. Try nftables
    let nft_result = tokio::process::Command::new("nft")
        .args([
            "add",
            "element",
            "inet",
            "filter",
            "secnet_blocklist",
            &format!("{{ {} }}", ip_str),
        ])
        .output()
        .await;

    if let Ok(out) = nft_result {
        if out.status.success() {
            info!("✅ Successfully blocked IP {} via nftables", ip_str);
            return;
        }
    }

    // 2. Fallback to iptables
    let is_ipv6 = ip.is_ipv6();
    let iptables_cmd = if is_ipv6 { "ip6tables" } else { "iptables" };
    let ipt_result = tokio::process::Command::new(iptables_cmd)
        .args(["-I", "INPUT", "-s", &ip_str, "-j", "DROP"])
        .output()
        .await;

    match ipt_result {
        Ok(out) if out.status.success() => {
            info!("✅ Successfully blocked IP {} via {}", ip_str, iptables_cmd);
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            warn!(
                "⚠️ Firewall command failed (status: {}): {}. Running without CAP_NET_ADMIN/root?",
                out.status,
                err.trim()
            );
        }
        Err(e) => {
            warn!(
                "⚠️ Firewall command execution failed: {}. Continuing with database blocklist.",
                e
            );
        }
    }
}

/// Spawns background task to persist alerts to PostgreSQL, auto-block critical attackers, and dispatch them
pub fn spawn_alert_persister(mut alert_rx: Receiver<Alert>, pool: Option<Arc<PgPool>>) {
    let auto_block_enabled = std::env::var("AUTO_BLOCK_CRITICAL_IPS")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true);

    tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            // Auto-Response: If alert is Critical, auto-block attacker IP (if not in allowlist) (Mục 17)
            if auto_block_enabled && alert.severity == AlertSeverity::Critical {
                if is_allowlisted_ip(&alert.src_ip) {
                    info!(
                        "🛡️ [AUTO-RESPONSE] IP {} is in allowlist, skipping automated block.",
                        alert.src_ip
                    );
                } else {
                    info!("🚨 [AUTO-RESPONSE] Critical threat identified! Initiating automated response for IP {}", alert.src_ip);

                    // 1. Apply OS firewall block
                    apply_os_firewall_block(alert.src_ip).await;

                    // 2. Insert into database blocked_ips table
                    if let Some(ref pool) = pool {
                        let block_reason = format!(
                            "Auto-blocked by SecNet IPS due to Critical Alert: {}",
                            alert.title
                        );
                        let block_res = sqlx::query(
                            r#"
                            INSERT INTO blocked_ips (ip_address, reason, blocked_until)
                            VALUES ($1, $2, CURRENT_TIMESTAMP + INTERVAL '2 hours')
                            ON CONFLICT (ip_address) DO UPDATE SET blocked_until = CURRENT_TIMESTAMP + INTERVAL '2 hours'
                            "#,
                        )
                        .bind(alert.src_ip)
                        .bind(block_reason)
                        .execute(pool.as_ref())
                        .await;

                        if let Err(e) = block_res {
                            warn!("Failed to auto-insert IP into blocked_ips table: {}", e);
                        } else {
                            info!(
                                "🔒 Malicious IP {} registered in blocked_ips table (2h lockout)",
                                alert.src_ip
                            );
                        }
                    }
                }
            }

            if let Some(ref pool) = pool {
                let result = sqlx::query(
                    r#"
                    INSERT INTO alerts (id, rule_id, severity, title, description, src_ip, dst_ip, detected_at, status)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    "#,
                )
                .bind(alert.id)
                .bind(alert.rule_id)
                .bind(alert.severity)
                .bind(&alert.title)
                .bind(&alert.description)
                .bind(alert.src_ip)
                .bind(alert.dst_ip)
                .bind(alert.detected_at)
                .bind(alert.status)
                .execute(pool.as_ref())
                .await;

                if let Err(e) = result {
                    warn!("Failed to persist alert to database: {}", e);
                } else {
                    info!("Persisted alert {} successfully to database", alert.id);
                    // Explicitly broadcast alert event to PgListener (Mục 1)
                    let _ = sqlx::query("SELECT pg_notify('new_alert', $1)")
                        .bind(alert.id.to_string())
                        .execute(pool.as_ref())
                        .await;
                }
            }
        }
    });
}
