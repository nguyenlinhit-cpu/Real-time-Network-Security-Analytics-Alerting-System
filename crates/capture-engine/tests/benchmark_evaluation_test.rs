use capture_engine::detection::engine::DetectionEngine;
use chrono::Utc;
use common::models::{Alert, TrafficEvent};
use std::time::Instant;
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
        interface_name: "eth0".to_string(),
    }
}

#[tokio::test]
async fn test_pipeline_throughput_benchmark() {
    let (alert_tx, mut alert_rx) = mpsc::channel::<Alert>(10000);
    let mut engine = DetectionEngine::new(alert_tx);

    // Drain triggered alerts in background to avoid channel backpressure
    tokio::spawn(async move { while alert_rx.recv().await.is_some() {} });

    let total_packets = 20_000usize;
    let mut events = Vec::with_capacity(total_packets);

    for i in 0..total_packets {
        let port = (1024 + (i % 60000)) as i32;
        events.push(make_event(
            "192.168.1.100/32",
            "10.0.0.1/32",
            port,
            80,
            "TCP",
            "ACK",
            128,
        ));
    }

    let start = Instant::now();
    engine.process_batch(&events).await;
    let duration = start.elapsed();

    let pps = (total_packets as f64) / duration.as_secs_f64();
    println!(
        "⚡ [BENCHMARK] Processed {} packets in {:.4?} ({:.0} packets/sec)",
        total_packets, duration, pps
    );

    // Assert that throughput exceeds 10,000 packets/sec
    assert!(
        pps >= 10_000.0,
        "Expected pipeline throughput >= 10,000 pps, got {:.0} pps",
        pps
    );
}

#[tokio::test]
async fn test_detection_precision_and_recall_metrics() {
    let (alert_tx, mut alert_rx) = mpsc::channel::<Alert>(1000);
    let mut engine = DetectionEngine::new(alert_tx);

    let mut attack_events = Vec::new();
    let mut benign_events = Vec::new();

    // 1. Attack Class: Port Scan (1 attacker probing 30 unique ports)
    for p in 1..=30 {
        attack_events.push(make_event(
            "198.51.100.10/32",
            "192.168.1.50/32",
            50000 + p,
            p,
            "TCP",
            "SYN",
            60,
        ));
    }

    // 2. Attack Class: SYN Flood (250 rapid SYN packets targeting web server)
    for i in 0..250 {
        attack_events.push(make_event(
            "203.0.113.88/32",
            "192.168.1.80/32",
            40000 + (i % 1000),
            80,
            "TCP",
            "SYN",
            64,
        ));
    }

    // 3. Attack Class: SSH Brute Force (10 rapid failed connection initiations)
    for _ in 0..10 {
        attack_events.push(make_event(
            "198.51.100.22/32",
            "192.168.1.22/32",
            52000,
            22,
            "TCP",
            "RST",
            60,
        ));
    }

    // 4. Attack Class: DNS Tunneling (high entropy queries)
    attack_events.push(make_event(
        "192.168.1.111/32",
        "8.8.8.8/32",
        53001,
        53,
        "UDP",
        "DNS:a8f9c1b7e4d2f0a1c3b5d7e9f2a4c6e8.exfil.attacker.com",
        120,
    ));

    // 5. Benign Class: 500 normal traffic flows (typing SSH, normal DNS, established TCP ACK/PSH)
    for i in 0..500 {
        match i % 4 {
            0 => {
                // Legitimate DNS lookup (low entropy)
                benign_events.push(make_event(
                    "192.168.1.105/32",
                    "8.8.8.8/32",
                    54000 + (i % 500),
                    53,
                    "UDP",
                    "DNS:api.github.com",
                    80,
                ));
            }
            1 => {
                // Legitimate established web browsing (ACK)
                benign_events.push(make_event(
                    "192.168.1.105/32",
                    "104.16.12.34/32",
                    55000 + (i % 500),
                    443,
                    "TCP",
                    "ACK",
                    1400,
                ));
            }
            2 => {
                // Normal typing traffic over established SSH session (PSH, ACK - not SYN/RST)
                benign_events.push(make_event(
                    "192.168.1.105/32",
                    "192.168.1.22/32",
                    56000,
                    22,
                    "TCP",
                    "PSH,ACK",
                    96,
                ));
            }
            _ => {
                // Legitimate NTP sync
                benign_events.push(make_event(
                    "192.168.1.105/32",
                    "162.159.200.1/32",
                    123,
                    123,
                    "UDP",
                    "",
                    48,
                ));
            }
        }
    }

    // Process benign events first to verify zero false positives
    for event in &benign_events {
        engine.process_event(event).await;
    }

    let mut false_positives = 0;
    while alert_rx.try_recv().is_ok() {
        false_positives += 1;
    }

    // Process attack events to measure true detections
    for event in &attack_events {
        engine.process_event(event).await;
    }

    let mut true_positives = 0;
    let mut triggered_alerts = Vec::new();
    while let Ok(alert) = alert_rx.try_recv() {
        true_positives += 1;
        triggered_alerts.push(alert);
    }

    // Expected attacks: Port Scan (1), SYN Flood (1), Brute Force (1), DNS Tunnel (1)
    let expected_threat_types = 4;
    let precision = if true_positives + false_positives > 0 {
        (true_positives as f64) / ((true_positives + false_positives) as f64)
    } else {
        1.0
    };

    let recall = if expected_threat_types > 0 {
        (true_positives.min(expected_threat_types) as f64) / (expected_threat_types as f64)
    } else {
        1.0
    };

    let f1_score = if precision + recall > 0.0 {
        2.0 * (precision * recall) / (precision + recall)
    } else {
        0.0
    };

    println!("📊 [EVALUATION REPORT]");
    println!("   Benign Events: {}", benign_events.len());
    println!("   Attack Events: {}", attack_events.len());
    println!("   True Positives (Alerts): {}", true_positives);
    println!("   False Positives: {}", false_positives);
    println!("   Precision: {:.2}%", precision * 100.0);
    println!("   Recall: {:.2}%", recall * 100.0);
    println!("   F1-Score: {:.4}", f1_score);

    assert_eq!(
        false_positives, 0,
        "Expected zero false positives on benign traffic"
    );
    assert!(
        true_positives >= expected_threat_types,
        "Expected all 4 attack scenarios detected"
    );
    assert!(precision >= 0.95, "Expected Precision >= 95%");
    assert!(recall >= 0.95, "Expected Recall >= 95%");

    // Verify MITRE ATT&CK mapping on all generated alerts
    for alert in triggered_alerts {
        assert!(
            alert.mitre_tactic.is_some(),
            "Alert '{}' must have MITRE tactic",
            alert.title
        );
        assert!(
            alert.mitre_technique.is_some(),
            "Alert '{}' must have MITRE technique",
            alert.title
        );
    }
}
