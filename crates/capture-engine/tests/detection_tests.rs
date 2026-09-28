use capture_engine::detection::arp_spoof::ArpSpoofDetector;
use capture_engine::detection::brute_force::BruteForceDetector;
use capture_engine::detection::dns_tunneling::DnsTunnelDetector;
use capture_engine::detection::port_scan::PortScanDetector;
use capture_engine::detection::syn_flood::SynFloodDetector;
use capture_engine::detection::zscore_anomaly::ZScoreAnomalyDetector;
use capture_engine::detection::DetectionRule;
use chrono::Utc;
use common::models::{AlertSeverity, TrafficEvent};
use tokio::sync::mpsc;
use uuid::Uuid;

fn make_event(
    src: &str,
    dst: &str,
    src_port: i32,
    dst_port: i32,
    protocol: &str,
    flags: &str,
    bytes: i64,
) -> TrafficEvent {
    TrafficEvent {
        time: Utc::now(),
        id: Uuid::new_v4(),
        src_ip: src.parse().unwrap(),
        dst_ip: dst.parse().unwrap(),
        src_port,
        dst_port,
        protocol: protocol.to_string(),
        bytes_transferred: bytes,
        packet_count: 1,
        flags: flags.to_string(),
        interface_name: "test0".to_string(),
    }
}

#[test]
fn test_port_scan_detector_triggers_and_rejects_normal() {
    let mut detector = PortScanDetector::new(5, 10);

    // Normal traffic: 2 distinct ports
    assert!(detector
        .evaluate(&make_event(
            "10.0.0.1/32",
            "192.168.1.1/32",
            40001,
            80,
            "TCP",
            "SYN",
            64
        ))
        .is_none());
    assert!(detector
        .evaluate(&make_event(
            "10.0.0.1/32",
            "192.168.1.1/32",
            40002,
            443,
            "TCP",
            "SYN",
            64
        ))
        .is_none());

    // Attack simulation: connect to 3 more distinct ports -> hits threshold 5
    assert!(detector
        .evaluate(&make_event(
            "10.0.0.1/32",
            "192.168.1.1/32",
            40003,
            22,
            "TCP",
            "SYN",
            64
        ))
        .is_none());
    assert!(detector
        .evaluate(&make_event(
            "10.0.0.1/32",
            "192.168.1.1/32",
            40004,
            21,
            "TCP",
            "SYN",
            64
        ))
        .is_none());
    let alert = detector.evaluate(&make_event(
        "10.0.0.1/32",
        "192.168.1.1/32",
        40005,
        3389,
        "TCP",
        "SYN",
        64,
    ));

    assert!(
        alert.is_some(),
        "Port scan should trigger on 5 distinct ports"
    );
    let a = alert.unwrap();
    assert_eq!(a.severity, AlertSeverity::High);
    assert!(a.title.contains("Port Scan"));
}

#[test]
fn test_syn_flood_detector_triggers_and_rejects_ack() {
    let mut detector = SynFloodDetector::new(4, 5);

    // Normal ACK packets should not trigger
    for _ in 0..10 {
        assert!(detector
            .evaluate(&make_event(
                "10.0.0.2/32",
                "192.168.1.50/32",
                50000,
                80,
                "TCP",
                "ACK",
                100
            ))
            .is_none());
    }

    // SYN packets
    assert!(detector
        .evaluate(&make_event(
            "10.0.0.2/32",
            "192.168.1.50/32",
            50001,
            80,
            "TCP",
            "SYN",
            64
        ))
        .is_none());
    assert!(detector
        .evaluate(&make_event(
            "10.0.0.2/32",
            "192.168.1.50/32",
            50002,
            80,
            "TCP",
            "SYN",
            64
        ))
        .is_none());
    assert!(detector
        .evaluate(&make_event(
            "10.0.0.2/32",
            "192.168.1.50/32",
            50003,
            80,
            "TCP",
            "SYN",
            64
        ))
        .is_none());
    let alert = detector.evaluate(&make_event(
        "10.0.0.2/32",
        "192.168.1.50/32",
        50004,
        80,
        "TCP",
        "SYN",
        64,
    ));

    assert!(
        alert.is_some(),
        "SYN flood should trigger when threshold of 4 is reached"
    );
    let alert = alert.unwrap();
    assert_eq!(alert.severity, AlertSeverity::Critical);
    // Single dominant source: attribution is trustworthy.
    assert_eq!(alert.src_ip, "10.0.0.2/32".parse().unwrap());
    assert!(detector.last_alert_auto_blockable());
}


#[test]
fn test_brute_force_detector_triggers_on_sensitive_ports() {
    let mut detector = BruteForceDetector::new(3, 10);

    // Failed attempts on port 22 (SSH)
    assert!(detector
        .evaluate(&make_event(
            "192.168.1.99/32",
            "192.168.1.50/32",
            51001,
            22,
            "TCP",
            "SYN,RST",
            120
        ))
        .is_none());
    assert!(detector
        .evaluate(&make_event(
            "192.168.1.99/32",
            "192.168.1.50/32",
            51002,
            22,
            "TCP",
            "SYN,RST",
            120
        ))
        .is_none());
    let alert = detector.evaluate(&make_event(
        "192.168.1.99/32",
        "192.168.1.50/32",
        51003,
        22,
        "TCP",
        "SYN,RST",
        120,
    ));

    assert!(
        alert.is_some(),
        "Brute-force should trigger on 3 failed attempts on SSH port 22"
    );
    assert!(alert.unwrap().title.contains("Brute-Force"));
}

#[test]
fn test_arp_spoof_detector_triggers_on_mac_change() {
    let mut detector = ArpSpoofDetector::new();

    // Initial legitimate MAC
    assert!(detector
        .evaluate(&make_event(
            "192.168.1.1/32",
            "192.168.1.1/32",
            0,
            0,
            "ARP",
            "MAC:00:11:22:33:44:55",
            42
        ))
        .is_none());

    // Consistent MAC -> no alert
    assert!(detector
        .evaluate(&make_event(
            "192.168.1.1/32",
            "192.168.1.1/32",
            0,
            0,
            "ARP",
            "MAC:00:11:22:33:44:55",
            42
        ))
        .is_none());

    // Attacker sends a forged ARP reply claiming 192.168.1.1 (sender IP) is at its own MAC
    let alert = detector.evaluate(&make_event(
        "192.168.1.1/32",
        "192.168.1.100/32",
        0,
        0,
        "ARP",
        "MAC:aa:bb:cc:dd:ee:ff",
        42,
    ));
    assert!(
        alert.is_some(),
        "ARP spoofing should trigger on MAC address change"
    );
    let alert = alert.unwrap();
    assert_eq!(alert.severity, AlertSeverity::Critical);
    assert!(alert.description.contains("aa:bb:cc:dd:ee:ff"));
    // The claimed IP is the victim: must never be auto-blocked.
    assert!(!detector.last_alert_auto_blockable());
}

#[test]
fn test_arp_requests_from_different_hosts_are_not_spoofing() {
    let mut detector = ArpSpoofDetector::new();
    // Two hosts asking for the same gateway: different senders, different MACs -> no alert.
    for (sender, mac) in [
        ("192.168.1.10/32", "MAC:00:00:00:00:00:10"),
        ("192.168.1.11/32", "MAC:00:00:00:00:00:11"),
        ("192.168.1.10/32", "MAC:00:00:00:00:00:10"),
    ] {
        assert!(detector
            .evaluate(&make_event(sender, "192.168.1.1/32", 0, 0, "ARP", mac, 42))
            .is_none());
    }
}

#[test]
fn test_dns_tunneling_detector_entropy() {
    let mut detector = DnsTunnelDetector::new(3.5, 20);

    // Normal DNS query with low entropy and short length
    assert!(detector
        .evaluate(&make_event(
            "192.168.1.5/32",
            "8.8.8.8/32",
            54321,
            53,
            "UDP",
            "DNS:google.com",
            60
        ))
        .is_none());

    // Exfiltration DNS query with high entropy random hex payload
    let exfil = "DNS:a98fcb391740d027bca402319ef182a09c.tunnel.org";
    let alert = detector.evaluate(&make_event(
        "192.168.1.5/32",
        "8.8.8.8/32",
        54322,
        53,
        "UDP",
        exfil,
        250,
    ));
    assert!(
        alert.is_some(),
        "DNS tunneling should trigger on high-entropy long subdomains"
    );
}

#[test]
fn test_zscore_anomaly_detector_detects_volume_spike() {
    let mut detector = ZScoreAnomalyDetector::new(2.5, 30);
    let base = Utc::now() - chrono::Duration::seconds(60);
    let at = |secs: i64, bytes: i64| {
        let mut e = make_event("10.0.0.1/32", "10.0.0.2/32", 5000, 80, "TCP", "ACK", bytes);
        e.time = base + chrono::Duration::seconds(secs);
        e
    };

    // 20 seconds of steady ~10 KB/s traffic (10 packets per second)
    for sec in 0..20 {
        for i in 0..10 {
            assert!(
                detector.evaluate(&at(sec, 900 + i * 20)).is_none(),
                "steady traffic must not alert"
            );
        }
    }

    // A single large packet is NOT a volume anomaly on its own (was a false positive)
    assert!(detector.evaluate(&at(20, 1500)).is_none());

    // One second of bulk transfer (50x the usual volume)...
    for _ in 0..10 {
        assert!(detector.evaluate(&at(21, 50_000)).is_none());
    }
    // ...is reported once that second's bucket closes.
    let alert = detector.evaluate(&at(22, 1000));
    assert!(
        alert.is_some(),
        "Z-Score anomaly detector should detect massive volume spike"
    );
    assert!(alert.unwrap().description.contains("bytes/s"));
}

#[test]
fn test_icmp_flood_detector_triggers_on_high_packet_rate() {
    use capture_engine::detection::icmp_flood::IcmpFloodDetector;
    let mut detector = IcmpFloodDetector::new(5, 5);

    // Normal non-ICMP packets should NOT trigger
    for _ in 0..10 {
        assert!(detector
            .evaluate(&make_event(
                "10.0.0.5/32",
                "192.168.1.1/32",
                0,
                0,
                "TCP",
                "ACK",
                64
            ))
            .is_none());
    }

    // 4 ICMP packets -> below threshold
    for _ in 0..4 {
        assert!(detector
            .evaluate(&make_event(
                "10.0.0.5/32",
                "192.168.1.1/32",
                0,
                0,
                "ICMP",
                "",
                64
            ))
            .is_none());
    }

    // 5th ICMP packet -> hits threshold
    let alert = detector.evaluate(&make_event(
        "10.0.0.5/32",
        "192.168.1.1/32",
        0,
        0,
        "ICMP",
        "",
        64,
    ));
    assert!(
        alert.is_some(),
        "ICMP flood detector must trigger when threshold is reached"
    );
    let a = alert.unwrap();
    assert_eq!(a.severity, AlertSeverity::High);
    assert!(a.title.contains("ICMP Flood"));
}

#[test]
fn test_beaconing_detector_triggers_on_periodic_callbacks() {
    use capture_engine::detection::beaconing::BeaconingDetector;
    let mut detector = BeaconingDetector::new(5, 0.20);

    // Simulate periodic SYN packets until detection
    let mut alert = None;
    for _ in 0..6 {
        if let Some(a) = detector.evaluate(&make_event(
            "192.168.1.80/32",
            "45.33.32.156/32",
            49152,
            443,
            "TCP",
            "SYN",
            64,
        )) {
            alert = Some(a);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(60));
    }

    assert!(
        alert.is_some(),
        "Beaconing detector must trigger on regular periodic callback intervals"
    );
    let a = alert.unwrap();
    assert_eq!(a.severity, AlertSeverity::High);
    assert!(a.title.contains("Beaconing"));
}

#[tokio::test]
async fn test_detection_engine_state_snapshot_and_restore() {
    use capture_engine::detection::engine::DetectionEngine;
    let (tx, _rx) = mpsc::channel(100);
    let mut engine1 = DetectionEngine::new(tx.clone());

    // Inject traffic to populate state (e.g. learn MAC address)
    engine1
        .process_event(&make_event(
            "192.168.1.10/32",
            "192.168.1.1/32",
            0,
            0,
            "ARP",
            "MAC:00:11:22:33:44:55",
            42,
        ))
        .await;

    // Snapshot state
    let snapshot = engine1.snapshot_state();
    assert!(!snapshot.to_string().is_empty());

    // Create a new fresh engine and restore state
    let mut engine2 = DetectionEngine::new(tx);
    engine2.restore_state(&snapshot);

    // Now attack engine3 with a forged ARP reply claiming the learned IP
    let (alert_tx2, mut alert_rx2) = mpsc::channel(100);
    let mut engine3 = DetectionEngine::new(alert_tx2);
    engine3.restore_state(&snapshot);

    engine3
        .process_event(&make_event(
            "192.168.1.10/32",
            "192.168.1.1/32",
            0,
            0,
            "ARP",
            "MAC:de:ad:be:ef:00:01",
            42,
        ))
        .await;

    // An alert should have been generated because engine3 remembers the old MAC!
    let received_alert = alert_rx2.try_recv();
    assert!(
        received_alert.is_ok(),
        "Restored engine should immediately detect ARP spoofing from warmed-up state"
    );
}

#[test]
fn test_rule_config_dynamic_update() {
    let mut detector = PortScanDetector::new(5, 10);
    assert!(detector.is_enabled());

    let updated_config = common::models::DetectionRule {
        id: Uuid::new_v4(),
        name: "Port Scan Detection".to_string(),
        rule_type: common::models::RuleType::Threshold,
        condition_json: serde_json::json!({}),
        severity: common::models::AlertSeverity::Critical,
        is_enabled: false,
        threshold_value: 50.0,
        time_window_seconds: 120,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        mitre_tactic: Some("Discovery".to_string()),
        mitre_technique: Some("T1046".to_string()),
    };

    detector.update_config(&updated_config);
    assert!(
        !detector.is_enabled(),
        "Rule should be disabled after dynamic update"
    );

    // When disabled, even extensive port scanning should not trigger alert
    for p in 1..=30 {
        assert!(detector
            .evaluate(&make_event(
                "10.0.0.1/32",
                "192.168.1.1/32",
                40000 + p,
                p,
                "TCP",
                "SYN",
                64
            ))
            .is_none());
    }
}

#[test]
fn test_syn_flood_distributed_sources_not_auto_blockable() {
    let mut detector = SynFloodDetector::new(10, 5);
    let mut alert = None;
    for i in 0..10 {
        let src = format!("198.51.100.{}/32", i + 1);
        alert = detector.evaluate(&make_event(&src, "192.168.1.50/32", 40000, 80, "TCP", "SYN", 40));
    }
    let alert = alert.expect("distributed flood must still be detected");
    assert!(alert.description.contains("distinct sources"));
    assert!(
        !detector.last_alert_auto_blockable(),
        "no single source dominates: must not auto-block a random sender"
    );
}

#[test]
fn test_dns_tunneling_deduplicates_per_base_domain() {
    let mut detector = DnsTunnelDetector::new(3.5, 20);
    let mut alerts = 0;
    for i in 0..15 {
        let _ = i;
        let flags = format!("DNS:{}.c2.tunnel-exfil.net", Uuid::new_v4().simple());
        if detector
            .evaluate(&make_event("192.168.1.188/32", "8.8.8.8/32", 50000, 53, "UDP", &flags, 120))
            .is_some()
        {
            alerts += 1;
        }
    }
    assert_eq!(alerts, 1, "one exfiltration session must produce a single alert");
}

fn rule_model(name: &str, severity: AlertSeverity, threshold: f64, window: i32) -> common::models::DetectionRule {
    common::models::DetectionRule {
        id: Uuid::new_v4(),
        name: name.to_string(),
        rule_type: common::models::RuleType::Threshold,
        condition_json: serde_json::json!({}),
        severity,
        is_enabled: true,
        threshold_value: threshold,
        time_window_seconds: window,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        mitre_tactic: Some("Reconnaissance".to_string()),
        mitre_technique: Some("T1595".to_string()),
    }
}

async fn run_port_scan(engine: &mut capture_engine::detection::engine::DetectionEngine) {
    for p in 1..=20 {
        engine
            .process_event(&make_event("10.9.9.9/32", "192.168.1.50/32", 40000, 1000 + p, "TCP", "SYN", 64))
            .await;
    }
}

#[tokio::test]
async fn test_engine_applies_db_severity_and_disables_deleted_rules() {
    use capture_engine::detection::engine::DetectionEngine;
    let (tx, mut rx) = mpsc::channel(100);
    let mut engine = DetectionEngine::new(tx);

    // Port scan configured from the DB with a custom severity and MITRE mapping
    let cfg = rule_model("Port Scan Detection", AlertSeverity::Low, 5.0, 10);
    let cfg_id = cfg.id;
    engine.apply_rule_configs(vec![cfg]);
    run_port_scan(&mut engine).await;
    let alert = rx.try_recv().expect("port scan alert expected");
    assert_eq!(alert.rule_id, Some(cfg_id));
    assert_eq!(alert.severity, AlertSeverity::Low, "severity must come from the DB rule");
    assert_eq!(alert.mitre_technique.as_deref(), Some("T1595"));

    // Rule deleted in the UI (DB synced without it): the detector must stop, instead of
    // producing alerts with a dangling rule id.
    let (tx2, mut rx2) = mpsc::channel(100);
    let mut engine2 = DetectionEngine::new(tx2);
    engine2.apply_rule_configs(vec![]);
    run_port_scan(&mut engine2).await;
    assert!(rx2.try_recv().is_err(), "deleted rule must not produce alerts");
}

#[tokio::test]
async fn test_engine_executes_custom_rules() {
    use capture_engine::detection::engine::DetectionEngine;
    let (tx, mut rx) = mpsc::channel(100);
    let mut engine = DetectionEngine::new(tx);

    let mut custom = rule_model("Telnet burst", AlertSeverity::High, 5.0, 10);
    custom.condition_json = serde_json::json!({"metric": "packet_rate", "group_by": "src_ip", "dst_port": 23});
    let custom_id = custom.id;
    engine.apply_rule_configs(vec![custom]);

    for _ in 0..5 {
        engine
            .process_event(&make_event("10.1.2.3/32", "192.168.1.9/32", 40000, 23, "TCP", "ACK", 64))
            .await;
    }
    let alert = rx.try_recv().expect("custom rule must fire");
    assert_eq!(alert.rule_id, Some(custom_id));
    assert_eq!(alert.severity, AlertSeverity::High);
    assert!(alert.title.contains("Telnet burst"));
}

#[tokio::test]
async fn test_simulator_covers_all_eight_detectors() {
    use capture_engine::capture::simulator::{AttackScenario, TrafficSimulator};
    use capture_engine::capture::PacketSource;
    use capture_engine::detection::engine::DetectionEngine;
    use std::collections::HashSet;

    let (tx, mut rx) = mpsc::channel(10_000);
    let mut engine = DetectionEngine::new(tx);
    let mut sim = TrafficSimulator::new("sim0".to_string());

    // 15 seconds of historical background traffic: baseline for the per-second volume detector
    let now = Utc::now();
    for s in 0..15i64 {
        for _ in 0..20 {
            let mut e = sim.generate_normal_event();
            e.time = now - chrono::Duration::seconds(16 - s);
            engine.process_event(&e).await;
        }
    }
    // Make sure the gateway binding is known before the spoof
    engine
        .process_event(&make_event(
            capture_engine::capture::simulator::GATEWAY_IP,
            "192.168.1.100/32",
            0,
            0,
            "ARP",
            &format!("MAC:{}", capture_engine::capture::simulator::GATEWAY_MAC),
            42,
        ))
        .await;

    for (name, scenario) in AttackScenario::demo_rotation() {
        sim.set_scenario(scenario);
        let started = std::time::Instant::now();
        while !sim.is_idle() && started.elapsed() < std::time::Duration::from_secs(20) {
            let e = sim.next_event().await.unwrap();
            engine.process_event(&e).await;
            // Volume spike and beaconing are time based
            if name == "volume_spike" || name == "beaconing" {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        }
        // Close the traffic-volume bucket with one more second of normal traffic
        let until = std::time::Instant::now() + std::time::Duration::from_millis(1100);
        while std::time::Instant::now() < until {
            let e = sim.next_event().await.unwrap();
            engine.process_event(&e).await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    let mut titles = HashSet::new();
    while let Ok(a) = rx.try_recv() {
        titles.insert(a.mitre_technique.clone().unwrap_or_default());
    }
    for technique in ["T1046", "T1498", "T1110", "T1557", "T1071.004", "T1020", "T1498.001", "T1071"] {
        assert!(
            titles.contains(technique),
            "scenario for {} produced no alert (got {:?})",
            technique,
            titles
        );
    }
}
