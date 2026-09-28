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
    assert_eq!(alert.unwrap().severity, AlertSeverity::Critical);
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

    // Attacker spoofing MAC for 192.168.1.1
    let alert = detector.evaluate(&make_event(
        "192.168.1.200/32",
        "192.168.1.1/32",
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
    assert_eq!(alert.unwrap().severity, AlertSeverity::Critical);
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

    // Train baseline with normal 100-byte packets
    for _ in 0..20 {
        assert!(detector
            .evaluate(&make_event(
                "10.0.0.1/32",
                "10.0.0.2/32",
                5000,
                80,
                "TCP",
                "ACK",
                100
            ))
            .is_none());
    }

    // Massive sudden spike
    let alert = detector.evaluate(&make_event(
        "10.0.0.1/32",
        "10.0.0.2/32",
        5000,
        80,
        "TCP",
        "ACK",
        500_000,
    ));
    assert!(
        alert.is_some(),
        "Z-Score anomaly detector should detect massive volume spike"
    );
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

    // Now attack engine2 with spoofed MAC for the same target IP
    let (alert_tx2, mut alert_rx2) = mpsc::channel(100);
    let mut engine3 = DetectionEngine::new(alert_tx2);
    engine3.restore_state(&snapshot);

    engine3
        .process_event(&make_event(
            "192.168.1.99/32",
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
