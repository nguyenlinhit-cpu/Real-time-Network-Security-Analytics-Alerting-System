use common::models::{Alert, AlertSeverity, DetectionRule as RuleModel, TrafficEvent};
use ipnetwork::IpNetwork;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, info, warn};

use super::arp_spoof::ArpSpoofDetector;
use super::beaconing::BeaconingDetector;
use super::brute_force::BruteForceDetector;
use super::dns_tunneling::DnsTunnelDetector;
use super::generic_threshold::GenericThresholdDetector;
use super::icmp_flood::IcmpFloodDetector;
use super::port_scan::PortScanDetector;
use super::syn_flood::SynFloodDetector;
use super::zscore_anomaly::ZScoreAnomalyDetector;
use super::DetectionRule;

/// Historical names used by older seeds for the built-in detectors.
const RULE_ALIASES: [(&str, &str); 2] = [
    ("Brute-force Attack Detection", "SSH/RDP Brute-Force Detection"),
    ("ARP Spoofing / Poisoning Detection", "ARP Spoofing Detection"),
];

fn matches_builtin(builtin: &str, db_name: &str) -> bool {
    builtin == db_name
        || RULE_ALIASES
            .iter()
            .any(|(b, alias)| *b == builtin && *alias == db_name)
}

pub struct DetectionEngine {
    rules: Vec<Box<dyn DetectionRule>>,
    /// DB configuration for each built-in detector (same index as `rules`).
    rule_configs: Vec<Option<RuleModel>>,
    /// User-defined rules from the UI, executed by the generic threshold detector.
    custom_rules: Vec<GenericThresholdDetector>,
    /// Once rules were loaded from the DB, a built-in without a DB row is treated as deleted.
    db_synced: bool,
    alert_tx: Sender<Alert>,
    block_tx: Option<Sender<IpNetwork>>,
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
        let rule_configs = vec![None; rules.len()];

        Self {
            rules,
            rule_configs,
            custom_rules: Vec::new(),
            db_synced: false,
            alert_tx,
            block_tx: None,
        }
    }

    /// Enables automated response: source IPs of critical alerts with a trustworthy attribution
    /// are sent to `block_tx`.
    pub fn set_block_sender(&mut self, block_tx: Sender<IpNetwork>) {
        self.block_tx = Some(block_tx);
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
        Ok(())
    }

    /// Load state from file
    pub fn load_state_from_file(&mut self, path: &str) -> Result<(), std::io::Error> {
        if std::path::Path::new(path).exists() {
            let content = std::fs::read_to_string(path)?;
            match serde_json::from_str(&content) {
                Ok(json) => {
                    self.restore_state(&json);
                    info!("Loaded rule state snapshot from {}", path);
                }
                Err(e) => warn!("Ignoring corrupt rule state file {}: {}", path, e),
            }
        }
        Ok(())
    }

    /// Applies the rule set from the database: configures built-in detectors, disables built-ins
    /// whose rule was deleted, and (re)builds user-defined rules.
    pub fn apply_rule_configs(&mut self, db_rules: Vec<RuleModel>) {
        let mut remaining: HashMap<uuid::Uuid, RuleModel> =
            db_rules.into_iter().map(|r| (r.id, r)).collect();

        for (idx, rule) in self.rules.iter_mut().enumerate() {
            let found = remaining
                .values()
                .find(|r| matches_builtin(rule.name(), &r.name))
                .map(|r| r.id);
            match found.and_then(|id| remaining.remove(&id)) {
                Some(cfg) => {
                    rule.update_config(&cfg);
                    self.rule_configs[idx] = Some(cfg);
                }
                None => {
                    if self.rule_configs[idx].is_some() || !self.db_synced {
                        info!(
                            "Built-in rule '{}' has no database entry; detector disabled",
                            rule.name()
                        );
                    }
                    self.rule_configs[idx] = None;
                }
            }
        }

        // Everything left is a custom rule.
        let mut previous: HashMap<uuid::Uuid, GenericThresholdDetector> = self
            .custom_rules
            .drain(..)
            .map(|d| (d.rule_id(), d))
            .collect();
        let mut custom: Vec<GenericThresholdDetector> = remaining
            .into_values()
            .map(|cfg| match previous.remove(&cfg.id) {
                Some(mut existing) => {
                    existing.update_config(&cfg);
                    existing
                }
                None => GenericThresholdDetector::from_config(&cfg),
            })
            .collect();
        custom.sort_by(|a, b| a.name().cmp(b.name()));
        self.custom_rules = custom;
        self.db_synced = true;

        info!(
            "Rule configuration applied: {} built-in active, {} custom rule(s)",
            self.rule_configs.iter().filter(|c| c.is_some()).count(),
            self.custom_rules.len()
        );
    }

    /// Update detection rules dynamically from database configuration
    pub async fn reload_rules_from_db(&mut self, pool: &PgPool) -> Result<(), sqlx::Error> {
        let db_rules = sqlx::query_as::<_, RuleModel>(
            "SELECT id, name, rule_type, condition_json, severity, is_enabled, threshold_value, time_window_seconds, created_at, updated_at, mitre_tactic, mitre_technique FROM detection_rules"
        )
        .fetch_all(pool)
        .await?;
        self.apply_rule_configs(db_rules);
        Ok(())
    }

    /// Periodically cleans up stale internal state across all rules (Mục 30)
    pub fn cleanup_stale_state(&mut self, max_age: std::time::Duration) {
        for rule in &mut self.rules {
            rule.cleanup_stale(max_age);
        }
        for rule in &mut self.custom_rules {
            rule.cleanup_stale(max_age);
        }
    }

    /// Stamps the DB configuration (rule id, severity, MITRE mapping) onto a detector alert.
    fn apply_overrides(alert: &mut Alert, cfg: &RuleModel) {
        alert.rule_id = Some(cfg.id);
        alert.severity = cfg.severity;
        if cfg.mitre_tactic.is_some() {
            alert.mitre_tactic = cfg.mitre_tactic.clone();
        }
        if cfg.mitre_technique.is_some() {
            alert.mitre_technique = cfg.mitre_technique.clone();
        }
    }

    async fn emit(&self, alert: Alert, auto_blockable: bool) {
        info!(
            "🚨 [ALERT TRIGGERED] {} - {}",
            alert.title, alert.description
        );
        if auto_blockable && alert.severity == AlertSeverity::Critical {
            if let Some(tx) = &self.block_tx {
                if tx.try_send(alert.src_ip).is_err() {
                    warn!("Auto-block queue full; skipping block of {}", alert.src_ip);
                }
            }
        }
        if let Err(e) = self.alert_tx.send(alert).await {
            error!("Failed to forward alert to alerting channel: {}", e);
        }
    }

    /// Process a single event through all detection rules
    pub async fn process_event(&mut self, event: &TrafficEvent) {
        let mut produced: Vec<(Alert, bool)> = Vec::new();

        for (idx, rule) in self.rules.iter_mut().enumerate() {
            let cfg = &self.rule_configs[idx];
            if self.db_synced && cfg.is_none() {
                continue; // rule deleted in the UI
            }
            if let Some(mut alert) = rule.evaluate(event) {
                if let Some(cfg) = cfg {
                    Self::apply_overrides(&mut alert, cfg);
                } else {
                    alert.rule_id = None;
                }
                produced.push((alert, rule.last_alert_auto_blockable()));
            }
        }
        for rule in &mut self.custom_rules {
            if let Some(alert) = rule.evaluate(event) {
                produced.push((alert, rule.last_alert_auto_blockable()));
            }
        }

        for (alert, blockable) in produced {
            self.emit(alert, blockable).await;
        }
    }

    /// Process a batch of events (optimized for high-throughput pipeline > 10,000 pkts/sec)
    pub async fn process_batch(&mut self, events: &[TrafficEvent]) {
        for event in events {
            self.process_event(event).await;
        }
    }
}

/// Infrastructure allowlist that auto-response must never block (Mục 17).
/// `ALLOWLIST_IPS` accepts comma-separated IPs or CIDRs and replaces the defaults.
pub fn is_allowlisted_ip(ip: &IpNetwork) -> bool {
    let addr = ip.ip();
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return true;
    }
    let list = std::env::var("ALLOWLIST_IPS")
        .unwrap_or_else(|_| "192.168.1.1,8.8.8.8,8.8.4.4,1.1.1.1".to_string());
    list.split(',')
        .filter_map(|s| s.trim().parse::<IpNetwork>().ok())
        .any(|net| net.contains(addr))
}

/// Records an automated block in `blocked_ips` for 2 hours.
pub fn spawn_auto_blocker(mut block_rx: Receiver<IpNetwork>, pool: Option<Arc<PgPool>>) {
    tokio::spawn(async move {
        while let Some(ip) = block_rx.recv().await {
            if is_allowlisted_ip(&ip) {
                info!(
                    "🛡️ [AUTO-RESPONSE] IP {} is in allowlist, skipping automated block.",
                    ip
                );
                continue;
            }
            let Some(ref pool) = pool else { continue };
            let res = sqlx::query(
                r#"
                INSERT INTO blocked_ips (ip_address, reason, blocked_until)
                VALUES ($1, $2, CURRENT_TIMESTAMP + INTERVAL '2 hours')
                ON CONFLICT (ip_address) DO UPDATE
                SET reason = EXCLUDED.reason,
                    blocked_until = GREATEST(blocked_ips.blocked_until, EXCLUDED.blocked_until)
                "#,
            )
            .bind(ip)
            .bind("Auto-blocked by SecNet IPS after a critical alert")
            .execute(pool.as_ref())
            .await;
            match res {
                Ok(_) => info!("🔒 [AUTO-RESPONSE] {} added to blocklist for 2 hours", ip),
                Err(e) => warn!("Failed to auto-insert IP into blocked_ips table: {}", e),
            }
        }
    });
}

async fn insert_alert(pool: &PgPool, alert: &Alert, rule_id: Option<uuid::Uuid>) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO alerts (id, rule_id, severity, title, description, src_ip, dst_ip, detected_at, status, mitre_tactic, mitre_technique)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(alert.id)
    .bind(rule_id)
    .bind(alert.severity)
    .bind(&alert.title)
    .bind(&alert.description)
    .bind(alert.src_ip)
    .bind(alert.dst_ip)
    .bind(alert.detected_at)
    .bind(alert.status)
    .bind(&alert.mitre_tactic)
    .bind(&alert.mitre_technique)
    .execute(pool)
    .await
    .map(|_| ())
}

/// Persists alerts. The `alerts` INSERT trigger publishes each new alert to the backend
/// (`pg_notify('new_alert')`), so no extra notification is sent here.
pub fn spawn_alert_persister(mut alert_rx: Receiver<Alert>, pool: Option<Arc<PgPool>>) {
    tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            let Some(ref pool) = pool else { continue };
            let mut result = insert_alert(pool, &alert, alert.rule_id).await;

            // The rule may have been deleted between detection and insert: keep the alert.
            if let Err(sqlx::Error::Database(ref db_err)) = result {
                if db_err.is_foreign_key_violation() && alert.rule_id.is_some() {
                    warn!("Rule of alert {} no longer exists; storing without rule link", alert.id);
                    result = insert_alert(pool, &alert, None).await;
                }
            }

            match result {
                Ok(()) => info!("Persisted alert {} successfully to database", alert.id),
                Err(e) => warn!("Failed to persist alert to database: {}", e),
            }
        }
    });
}

/// Mirrors the active blocklist into a dedicated iptables/ip6tables chain (`SECNET_BLOCK`),
/// rebuilding it every `interval`. Requires CAP_NET_ADMIN in the *host* network namespace
/// (`network_mode: host`); only enabled with `FIREWALL_ENFORCEMENT=true`.
pub fn spawn_firewall_sync(pool: Arc<PgPool>, interval: std::time::Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let ips: Vec<IpNetwork> = match sqlx::query_scalar(
                "SELECT ip_address FROM blocked_ips WHERE blocked_until IS NULL OR blocked_until > NOW()",
            )
            .fetch_all(pool.as_ref())
            .await
            {
                Ok(v) => v,
                Err(e) => {
                    warn!("Firewall sync: cannot read blocklist: {}", e);
                    continue;
                }
            };
            for (cmd, v6) in [("iptables", false), ("ip6tables", true)] {
                let wanted: Vec<String> = ips
                    .iter()
                    .filter(|ip| ip.is_ipv6() == v6)
                    .map(|ip| ip.to_string())
                    .collect();
                if let Err(e) = sync_chain(cmd, &wanted).await {
                    warn!("Firewall sync via {} failed: {}", cmd, e);
                }
            }
        }
    });
}

async fn run(cmd: &str, args: &[&str]) -> Result<bool, String> {
    tokio::process::Command::new(cmd)
        .args(args)
        .output()
        .await
        .map(|o| o.status.success())
        .map_err(|e| e.to_string())
}

async fn sync_chain(cmd: &str, ips: &[String]) -> Result<(), String> {
    const CHAIN: &str = "SECNET_BLOCK";
    // Create the chain (fails harmlessly if it exists) and hook it into INPUT once.
    let _ = run(cmd, &["-N", CHAIN]).await?;
    if !run(cmd, &["-C", "INPUT", "-j", CHAIN]).await? {
        run(cmd, &["-I", "INPUT", "-j", CHAIN]).await?;
    }
    if !run(cmd, &["-F", CHAIN]).await? {
        return Err(format!("cannot flush {} (missing CAP_NET_ADMIN?)", CHAIN));
    }
    for ip in ips {
        run(cmd, &["-A", CHAIN, "-s", ip, "-j", "DROP"]).await?;
    }
    Ok(())
}
