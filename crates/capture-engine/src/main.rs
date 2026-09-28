use capture_engine::capture::simulator::{AttackScenario, TrafficSimulator};
use capture_engine::capture::{live::LiveCapture, PacketSource};
use capture_engine::detection::engine::{spawn_alert_persister, DetectionEngine};
use common::models::{Alert, TrafficEvent};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

async fn flush_traffic_batch(events: &[TrafficEvent], pool: Option<&Arc<PgPool>>) {
    if events.is_empty() {
        return;
    }
    if let Some(p) = pool {
        // Broadcast sample event to PgListener for real-time WebSocket push (Mục 2)
        if let Some(sample) = events.last() {
            if let Ok(json_str) = serde_json::to_string(sample) {
                let _ = sqlx::query("SELECT pg_notify('new_traffic', $1)")
                    .bind(json_str)
                    .execute(p.as_ref())
                    .await;
            }
        }

        // Batch insert traffic events into TimescaleDB hypertable
        let mut query_builder = sqlx::QueryBuilder::new(
            "INSERT INTO traffic_events (time, id, src_ip, dst_ip, src_port, dst_port, protocol, bytes_transferred, packet_count, flags, interface_name) "
        );

        query_builder.push_values(events, |mut b, ev| {
            b.push_bind(ev.time)
                .push_bind(ev.id)
                .push_bind(ev.src_ip)
                .push_bind(ev.dst_ip)
                .push_bind(ev.src_port)
                .push_bind(ev.dst_port)
                .push_bind(&ev.protocol)
                .push_bind(ev.bytes_transferred)
                .push_bind(ev.packet_count)
                .push_bind(&ev.flags)
                .push_bind(&ev.interface_name);
        });

        let query = query_builder.build();
        if let Err(e) = query.execute(p.as_ref()).await {
            tracing::warn!(
                "Failed to persist batch of {} traffic events: {}",
                events.len(),
                e
            );
        } else {
            tracing::debug!("Persisted {} traffic events to TimescaleDB", events.len());
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("🛡️ ========================================================");
    info!("🛡️ Starting Real-time Network Security Detection Engine");
    info!("🛡️ ========================================================");

    let database_url = std::env::var("DATABASE_URL").ok();
    let simulation_mode = std::env::var("SIMULATION_MODE")
        .unwrap_or_else(|_| "true".to_string())
        .parse::<bool>()
        .unwrap_or(true);
    let interface_name = std::env::var("CAPTURE_INTERFACE").unwrap_or_else(|_| "eth0".to_string());

    // Connect to PostgreSQL/TimescaleDB if available
    let pool = if let Some(url) = database_url {
        match PgPoolOptions::new().max_connections(5).connect(&url).await {
            Ok(p) => {
                info!("Connected to database successfully: {}", url);
                Some(Arc::new(p))
            }
            Err(e) => {
                warn!(
                    "Could not connect to database (running in standalone memory mode): {}",
                    e
                );
                None
            }
        }
    } else {
        None
    };

    // Create channel for triggered alerts
    let (alert_tx, alert_rx) = mpsc::channel::<Alert>(1000);

    // Spawn alert persister background task
    spawn_alert_persister(alert_rx, pool.clone());

    // Create channel for captured traffic events to batch persist and stream (Mục 2)
    let (traffic_tx, mut traffic_rx) = mpsc::channel::<TrafficEvent>(5000);
    let pool_traffic = pool.clone();
    tokio::spawn(async move {
        let mut buffer: Vec<TrafficEvent> = Vec::with_capacity(100);
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                Some(event) = traffic_rx.recv() => {
                    buffer.push(event);
                    if buffer.len() >= 100 {
                        flush_traffic_batch(&buffer, pool_traffic.as_ref()).await;
                        buffer.clear();
                    }
                }
                _ = interval.tick() => {
                    if !buffer.is_empty() {
                        flush_traffic_batch(&buffer, pool_traffic.as_ref()).await;
                        buffer.clear();
                    }
                }
            }
        }
    });

    // Initialize detection engine
    let mut engine = DetectionEngine::new(alert_tx);

    let state_file = std::env::var("RULES_STATE_FILE")
        .unwrap_or_else(|_| "/tmp/secnet_rules_state.json".to_string());
    if let Err(e) = engine.load_state_from_file(&state_file) {
        warn!("Could not load rules state from {}: {}", state_file, e);
    }

    if let Some(ref p) = pool {
        if let Err(e) = engine.reload_rules_from_db(p.as_ref()).await {
            warn!("Could not load rules from DB, using defaults: {}", e);
        }
    }

    let engine = Arc::new(tokio::sync::Mutex::new(engine));

    // Listen for rule changes in PostgreSQL to hot-reload in real-time (Mục 6)
    if let Some(ref p) = pool {
        let pool_rules = p.clone();
        let engine_rules = engine.clone();
        tokio::spawn(async move {
            if let Ok(mut listener) =
                sqlx::postgres::PgListener::connect_with(pool_rules.as_ref()).await
            {
                if listener.listen("rules_changed").await.is_ok() {
                    info!("📡 Detection engine subscribed to 'rules_changed' notification channel");
                    while listener.recv().await.is_ok() {
                        info!("🔄 Rule change notification received! Reloading rules configuration from DB...");
                        let mut eng = engine_rules.lock().await;
                        let _ = eng.reload_rules_from_db(pool_rules.as_ref()).await;
                    }
                }
            }
        });
    }

    // Periodic state snapshotting background task (persists ARP cache, sliding windows every 30s)
    let engine_snapshot = engine.clone();
    let state_file_periodic = state_file.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            let eng = engine_snapshot.lock().await;
            if let Err(e) = eng.save_state_to_file(&state_file_periodic) {
                warn!("Periodic rule state snapshot failed: {}", e);
            } else {
                tracing::debug!(
                    "Periodic rule state snapshot saved to {}",
                    state_file_periodic
                );
            }
        }
    });

    // Periodic memory cleanup for stale detection state (Mục 30)
    let engine_cleanup = engine.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            let mut eng = engine_cleanup.lock().await;
            eng.cleanup_stale_state(Duration::from_secs(300));
            tracing::debug!("Cleaned up stale detection engine tracking state");
        }
    });

    // Periodic sensor heartbeat reporting (Mục 40 / C1.40)
    let pool_heartbeat = pool.clone();
    let interface_name_heartbeat = interface_name.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.tick().await;
        let sensor_id = std::env::var("SENSOR_ID")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "sensor-primary-node".to_string());
        let version = env!("CARGO_PKG_VERSION").to_string();

        loop {
            interval.tick().await;
            if let Some(ref p) = pool_heartbeat {
                let _ = sqlx::query(
                    r#"
                    INSERT INTO sensor_heartbeats (sensor_id, sensor_version, interface_name, packets_captured, packets_dropped, status, last_heartbeat)
                    VALUES ($1, $2, $3, 0, 0, 'healthy', CURRENT_TIMESTAMP)
                    ON CONFLICT (sensor_id) DO UPDATE SET
                        sensor_version = EXCLUDED.sensor_version,
                        interface_name = EXCLUDED.interface_name,
                        status = 'healthy',
                        last_heartbeat = CURRENT_TIMESTAMP
                    "#,
                )
                .bind(&sensor_id)
                .bind(&version)
                .bind(&interface_name_heartbeat)
                .execute(p.as_ref())
                .await;
            }
        }
    });

    if simulation_mode {
        info!(
            "Running in SIMULATION MODE on interface '{}'",
            interface_name
        );
        info!("Demo Attack Scenario can be triggered automatically.");

        let mut sim = TrafficSimulator::new(interface_name.clone());

        // Select attack scenario based on environment variable (or run demonstration cycle) (Mục 44)
        let scenario_type = std::env::var("DEMO_SCENARIO").unwrap_or_else(|_| "all".to_string());
        let packets_per_sec = std::env::var("SIMULATION_PACKETS_PER_SEC")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(20);
        let sleep_ms = 1000 / packets_per_sec.clamp(1, 1000);

        let engine_sim = engine.clone();
        let traffic_tx_sim = traffic_tx.clone();

        tokio::spawn(async move {
            let mut packet_count: u64 = 0;
            let mut scenario_idx = 0;
            let target_ip = "192.168.1.50/32".parse().unwrap();

            // Set fixed scenario if specified
            match scenario_type.to_lowercase().as_str() {
                "port_scan" => sim.set_scenario(AttackScenario::PortScan {
                    target_ip,
                    start_port: 20,
                    port_count: 30,
                }),
                "syn_flood" => sim.set_scenario(AttackScenario::SynFlood {
                    target_ip,
                    packet_count: 250,
                }),
                "brute_force" => sim.set_scenario(AttackScenario::BruteForce {
                    target_ip,
                    port: 22,
                    attempts: 10,
                }),
                "arp_spoof" => sim.set_scenario(AttackScenario::ArpSpoof {
                    target_ip: "192.168.1.1/32".parse().unwrap(),
                    fake_mac: "de:ad:be:ef:00:01".to_string(),
                }),
                "dns_tunnel" => sim.set_scenario(AttackScenario::DnsTunneling { query_count: 15 }),
                "volume_spike" => {
                    sim.set_scenario(AttackScenario::TrafficVolumeSpike { multiplier: 10 })
                }
                _ => {}
            }

            loop {
                // If "all", periodically rotate all 6 attack scenarios; otherwise periodically re-arm the selected demo scenario
                if packet_count.is_multiple_of(60) {
                    if scenario_type.eq_ignore_ascii_case("all") {
                        match scenario_idx % 6 {
                            0 => {
                                info!("▶️ [DEMO SCENARIO] Triggering Port Scan attack against 192.168.1.50");
                                sim.set_scenario(AttackScenario::PortScan {
                                    target_ip,
                                    start_port: 20,
                                    port_count: 30,
                                });
                            }
                            1 => {
                                info!("▶️ [DEMO SCENARIO] Triggering SYN Flood attack against 192.168.1.50");
                                sim.set_scenario(AttackScenario::SynFlood {
                                    target_ip,
                                    packet_count: 250,
                                });
                            }
                            2 => {
                                info!("▶️ [DEMO SCENARIO] Triggering SSH Brute-Force attack against 192.168.1.50:22");
                                sim.set_scenario(AttackScenario::BruteForce {
                                    target_ip,
                                    port: 22,
                                    attempts: 10,
                                });
                            }
                            3 => {
                                info!(
                                    "▶️ [DEMO SCENARIO] Triggering ARP Spoofing attack on 192.168.1.1"
                                );
                                sim.set_scenario(AttackScenario::ArpSpoof {
                                    target_ip: "192.168.1.1/32".parse().unwrap(),
                                    fake_mac: "de:ad:be:ef:00:01".to_string(),
                                });
                            }
                            4 => {
                                info!("▶️ [DEMO SCENARIO] Triggering DNS Tunneling exfiltration via 8.8.8.8");
                                sim.set_scenario(AttackScenario::DnsTunneling { query_count: 15 });
                            }
                            _ => {
                                info!("▶️ [DEMO SCENARIO] Triggering Traffic Volume Spike (Z-Score Anomaly)");
                                sim.set_scenario(AttackScenario::TrafficVolumeSpike {
                                    multiplier: 10,
                                });
                            }
                        }
                        scenario_idx += 1;
                    } else {
                        match scenario_type.to_lowercase().as_str() {
                            "port_scan" => sim.set_scenario(AttackScenario::PortScan {
                                target_ip,
                                start_port: 20,
                                port_count: 30,
                            }),
                            "syn_flood" => sim.set_scenario(AttackScenario::SynFlood {
                                target_ip,
                                packet_count: 250,
                            }),
                            "brute_force" => sim.set_scenario(AttackScenario::BruteForce {
                                target_ip,
                                port: 22,
                                attempts: 10,
                            }),
                            "arp_spoof" => sim.set_scenario(AttackScenario::ArpSpoof {
                                target_ip: "192.168.1.1/32".parse().unwrap(),
                                fake_mac: "de:ad:be:ef:00:01".to_string(),
                            }),
                            "dns_tunnel" | "dns_tunneling" => {
                                sim.set_scenario(AttackScenario::DnsTunneling { query_count: 15 })
                            }
                            "volume_spike" => {
                                sim.set_scenario(AttackScenario::TrafficVolumeSpike {
                                    multiplier: 10,
                                })
                            }
                            _ => {}
                        }
                    }
                }

                if let Some(event) = sim.next_event().await {
                    packet_count += 1;
                    engine_sim.lock().await.process_event(&event).await;
                    let _ = traffic_tx_sim.try_send(event);

                    if packet_count.is_multiple_of(100) {
                        info!("Processed {} simulated packets successfully", packet_count);
                    }
                }

                tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
            }
        });
    } else {
        info!(
            "Running in LIVE CAPTURE mode on interface '{}'",
            interface_name
        );
        match LiveCapture::new(&interface_name) {
            Ok(mut live) => {
                let engine_live = engine.clone();
                let traffic_tx_live = traffic_tx.clone();
                tokio::spawn(async move {
                    while let Some(event) = live.next_event().await {
                        engine_live.lock().await.process_event(&event).await;
                        let _ = traffic_tx_live.try_send(event);
                    }
                });
            }
            Err(e) => {
                warn!(
                    "Could not start live capture on interface '{}': {}. Switching to simulation.",
                    interface_name, e
                );
            }
        }
    }

    // Keep the main process running: Handle both SIGINT and SIGTERM (Mục 44)
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT signal, shutting down...");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM signal (e.g. docker stop), shutting down...");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }

    info!("Shutting down detection engine gracefully.");
    if let Err(e) = engine.lock().await.save_state_to_file(&state_file) {
        warn!("Could not save rules state to {}: {}", state_file, e);
    }
    Ok(())
}
