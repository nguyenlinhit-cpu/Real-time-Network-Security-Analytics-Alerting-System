use capture_engine::capture::simulator::{AttackScenario, TrafficSimulator};
use capture_engine::capture::{live::LiveCapture, PacketSource};
use capture_engine::detection::engine::{spawn_alert_persister, DetectionEngine};
use common::models::Alert;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv().ok();

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
                warn!("Could not connect to database (running in standalone memory mode): {}", e);
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

    if simulation_mode {
        info!("Running in SIMULATION MODE on interface '{}'", interface_name);
        info!("Demo Attack Scenario can be triggered automatically.");

        let mut sim = TrafficSimulator::new(interface_name.clone());

        // Select attack scenario based on environment variable (or run demonstration cycle)
        let scenario_type = std::env::var("DEMO_SCENARIO").unwrap_or_else(|_| "all".to_string());

        tokio::spawn(async move {
            let mut packet_count: u64 = 0;
            let mut scenario_idx = 0;

            loop {
                // Periodically rotate attack scenarios for demo purposes
                if packet_count % 50 == 0 {
                    let target_ip = "192.168.1.50/32".parse().unwrap();
                    match scenario_idx % 5 {
                        0 => {
                            info!("▶️ [DEMO SCENARIO] Triggering Port Scan attack against 192.168.1.50");
                            sim.set_scenario(AttackScenario::PortScan { target_ip, start_port: 20, port_count: 30 });
                        }
                        1 => {
                            info!("▶️ [DEMO SCENARIO] Triggering SYN Flood attack against 192.168.1.50");
                            sim.set_scenario(AttackScenario::SynFlood { target_ip, packet_count: 250 });
                        }
                        2 => {
                            info!("▶️ [DEMO SCENARIO] Triggering SSH Brute-Force attack against 192.168.1.50:22");
                            sim.set_scenario(AttackScenario::BruteForce { target_ip, port: 22, attempts: 10 });
                        }
                        3 => {
                            info!("▶️ [DEMO SCENARIO] Triggering ARP Spoofing attack on 192.168.1.1");
                            sim.set_scenario(AttackScenario::ArpSpoof {
                                target_ip: "192.168.1.1/32".parse().unwrap(),
                                fake_mac: "de:ad:be:ef:00:01".to_string(),
                            });
                        }
                        _ => {
                            info!("▶️ [DEMO SCENARIO] Triggering DNS Tunneling exfiltration via 8.8.8.8");
                            sim.set_scenario(AttackScenario::DnsTunneling { query_count: 15 });
                        }
                    }
                    scenario_idx += 1;
                }

                if let Some(event) = sim.next_event().await {
                    packet_count += 1;
                    engine.process_event(&event).await;

                    if packet_count % 100 == 0 {
                        info!("Processed {} simulated packets successfully", packet_count);
                    }
                }

                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
    } else {
        info!("Running in LIVE CAPTURE mode on interface '{}'", interface_name);
        match LiveCapture::new(&interface_name) {
            Ok(mut live) => {
                while let Some(event) = live.next_event().await {
                    engine.process_event(&event).await;
                }
            }
            Err(e) => {
                warn!("Could not start live capture on interface '{}': {}. Switching to simulation.", interface_name, e);
            }
        }
    }

    // Keep the main process running
    tokio::signal::ctrl_c().await?;
    info!("Shutting down detection engine gracefully.");
    if let Err(e) = engine.save_state_to_file(&state_file) {
        warn!("Could not save rules state to {}: {}", state_file, e);
    }
    Ok(())
}

