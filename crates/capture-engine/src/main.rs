use capture_engine::capture::simulator::{AttackScenario, TrafficSimulator};
use capture_engine::capture::{live::LiveCapture, PacketSource, SensorStats};
use capture_engine::detection::engine::{
    spawn_alert_persister, spawn_auto_blocker, spawn_firewall_sync, DetectionEngine,
};
use common::models::{Alert, TrafficBatchDto, TrafficEvent};
use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::PgPool;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};

/// Postgres NOTIFY payloads are limited to 8000 bytes; stay safely below.
const MAX_NOTIFY_BYTES: usize = 7500;
const SAMPLE_EVENTS_PER_BATCH: usize = 10;

fn env_flag(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|v| !matches!(v.to_lowercase().as_str(), "false" | "0" | "no" | "off"))
        .unwrap_or(default)
}

/// Hides the password part of a connection URL before it is logged.
fn redact_url(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.rsplit_once('@') {
            Some((creds, host)) => {
                let user = creds.split(':').next().unwrap_or("");
                format!("{}://{}:****@{}", scheme, user, host)
            }
            None => url.to_string(),
        },
        None => "<invalid url>".to_string(),
    }
}

/// Resolves `host:port` of a service URL (postgres://…, redis://…) so the live capture can
/// ignore the engine's own connections to it.
async fn service_endpoint(url: &str, default_port: u16) -> Vec<(IpAddr, u16)> {
    let Some((_, rest)) = url.split_once("://") else {
        return Vec::new();
    };
    let host_port = rest.rsplit('@').next().unwrap_or(rest);
    let host_port = host_port.split(['/', '?']).next().unwrap_or(host_port);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (host_port.to_string(), default_port),
    };
    let resolved = tokio::net::lookup_host(format!("{}:{}", host, port)).await;
    match resolved {
        Ok(addrs) => addrs.map(|a| (a.ip(), port)).collect(),
        Err(_) => Vec::new(),
    }
}

async fn connect_db(url: &str) -> Option<Arc<PgPool>> {
    // The database may still be starting (container boot); retry for about a minute before
    // falling back to standalone mode.
    for attempt in 1..=30 {
        match PgPoolOptions::new().max_connections(5).connect(url).await {
            Ok(p) => {
                info!("Connected to database: {}", redact_url(url));
                return Some(Arc::new(p));
            }
            Err(e) if attempt < 30 => {
                warn!("Database not reachable yet (attempt {}/30): {}", attempt, e);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => {
                error!(
                    "Could not connect to database; running in standalone mode (alerts are NOT persisted): {}",
                    e
                );
            }
        }
    }
    None
}

/// Publishes a compact batch summary for `/ws/traffic`: a few sample events plus totals for
/// the whole batch, kept under the NOTIFY payload limit.
fn traffic_notification(events: &[TrafficEvent]) -> Option<String> {
    let mut batch = TrafficBatchDto {
        events: events
            .iter()
            .rev()
            .take(SAMPLE_EVENTS_PER_BATCH)
            .cloned()
            .map(|mut e| {
                if e.flags.len() > 120 {
                    e.flags = e.flags.chars().take(120).collect();
                }
                e
            })
            .collect(),
        total_bytes: events.iter().map(|e| e.bytes_transferred).sum(),
        total_packets: events.iter().map(|e| e.packet_count as i64).sum(),
    };
    loop {
        let json = serde_json::to_string(&batch).ok()?;
        if json.len() <= MAX_NOTIFY_BYTES || batch.events.is_empty() {
            return Some(json);
        }
        batch.events.pop();
    }
}

async fn flush_traffic_batch(events: &[TrafficEvent], pool: &PgPool, stats: &SensorStats) {
    if events.is_empty() {
        return;
    }

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

    if let Err(e) = query_builder.build().execute(pool).await {
        stats.record_dropped(events.len() as u64);
        warn!(
            "Failed to persist batch of {} traffic events: {}",
            events.len(),
            e
        );
        return;
    }

    if let Some(payload) = traffic_notification(events) {
        if let Err(e) = sqlx::query("SELECT pg_notify('new_traffic', $1)")
            .bind(payload)
            .execute(pool)
            .await
        {
            warn!("Failed to publish live traffic update: {}", e);
        }
    }
}

fn spawn_traffic_writer(
    mut traffic_rx: mpsc::Receiver<TrafficEvent>,
    pool: Option<Arc<PgPool>>,
    stats: Arc<SensorStats>,
) {
    tokio::spawn(async move {
        let mut buffer: Vec<TrafficEvent> = Vec::with_capacity(100);
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                maybe_event = traffic_rx.recv() => {
                    let Some(event) = maybe_event else { break };
                    buffer.push(event);
                    if buffer.len() < 100 {
                        continue;
                    }
                }
                _ = interval.tick() => {
                    if buffer.is_empty() {
                        continue;
                    }
                }
            }
            if let Some(ref p) = pool {
                flush_traffic_batch(&buffer, p, &stats).await;
            }
            buffer.clear();
        }
    });
}

/// Hot-reloads rules when the `rules_changed` trigger fires, reconnecting after DB outages.
fn spawn_rule_listener(pool: Arc<PgPool>, engine: Arc<Mutex<DetectionEngine>>) {
    tokio::spawn(async move {
        loop {
            let mut listener = match PgListener::connect_with(pool.as_ref()).await {
                Ok(l) => l,
                Err(e) => {
                    warn!("rules_changed listener cannot connect: {}", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };
            if let Err(e) = listener.listen("rules_changed").await {
                warn!("Failed to LISTEN rules_changed: {}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            info!("📡 Detection engine subscribed to 'rules_changed' notification channel");
            // Pick up changes made while the listener was down.
            if let Err(e) = engine.lock().await.reload_rules_from_db(pool.as_ref()).await {
                warn!("Rule reload failed: {}", e);
            }

            loop {
                match listener.recv().await {
                    Ok(_) => {
                        info!("🔄 Rule change notification received; reloading rules from DB");
                        if let Err(e) = engine.lock().await.reload_rules_from_db(pool.as_ref()).await {
                            warn!("Rule reload failed: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("rules_changed listener lost connection: {}", e);
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        break;
                    }
                }
            }
        }
    });
}

fn spawn_heartbeat(pool: Arc<PgPool>, interface_name: String, stats: Arc<SensorStats>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        let sensor_id = std::env::var("SENSOR_ID")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "sensor-primary-node".to_string());
        let version = env!("CARGO_PKG_VERSION").to_string();

        loop {
            interval.tick().await;
            let (captured, dropped, failed) = stats.snapshot();
            let status = if failed { "failed" } else { "healthy" };
            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO sensor_heartbeats (sensor_id, sensor_version, interface_name, packets_captured, packets_dropped, status, last_heartbeat)
                VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
                ON CONFLICT (sensor_id) DO UPDATE SET
                    sensor_version = EXCLUDED.sensor_version,
                    interface_name = EXCLUDED.interface_name,
                    packets_captured = EXCLUDED.packets_captured,
                    packets_dropped = EXCLUDED.packets_dropped,
                    status = EXCLUDED.status,
                    last_heartbeat = CURRENT_TIMESTAMP
                "#,
            )
            .bind(&sensor_id)
            .bind(&version)
            .bind(&interface_name)
            .bind(captured)
            .bind(dropped)
            .bind(status)
            .execute(pool.as_ref())
            .await
            {
                warn!("Heartbeat write failed: {}", e);
            }
        }
    });
}

/// Feeds one event through detection and into the persistence queue.
async fn handle_event(
    event: TrafficEvent,
    engine: &Mutex<DetectionEngine>,
    traffic_tx: &mpsc::Sender<TrafficEvent>,
    stats: &SensorStats,
) {
    stats.record_captured();
    engine.lock().await.process_event(&event).await;
    if traffic_tx.try_send(event).is_err() {
        stats.record_dropped(1);
    }
}

fn spawn_simulation(
    interface_name: String,
    engine: Arc<Mutex<DetectionEngine>>,
    traffic_tx: mpsc::Sender<TrafficEvent>,
    stats: Arc<SensorStats>,
) {
    let scenario_type = std::env::var("DEMO_SCENARIO").unwrap_or_else(|_| "all".to_string());
    let packets_per_sec = std::env::var("SIMULATION_PACKETS_PER_SEC")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(20)
        .clamp(1, 1000);
    let sleep_ms = (1000 / packets_per_sec).max(1);
    // Background traffic between two attack scenarios (~8 s) so each attack stands on its own.
    let idle_gap_packets = (packets_per_sec * 8).max(40);

    let rotation: Vec<(&'static str, AttackScenario)> =
        if scenario_type.eq_ignore_ascii_case("all") {
            AttackScenario::demo_rotation()
        } else if scenario_type.eq_ignore_ascii_case("none") {
            Vec::new()
        } else {
            match AttackScenario::from_name(&scenario_type) {
                Some(s) => vec![("custom", s)],
                None => {
                    warn!("Unknown DEMO_SCENARIO '{}'; running background traffic only", scenario_type);
                    Vec::new()
                }
            }
        };

    info!(
        "Simulation: {} pkt/s background traffic, demo scenario '{}'",
        packets_per_sec, scenario_type
    );

    tokio::spawn(async move {
        let mut sim = TrafficSimulator::new(interface_name);
        let mut packet_count: u64 = 0;
        let mut idle_packets: u64 = 0;
        let mut scenario_idx = 0usize;

        loop {
            if sim.is_idle() && !rotation.is_empty() {
                idle_packets += 1;
                if idle_packets >= idle_gap_packets {
                    idle_packets = 0;
                    let (name, scenario) = &rotation[scenario_idx % rotation.len()];
                    info!("▶️ [DEMO SCENARIO] Triggering '{}' attack", name);
                    sim.set_scenario(scenario.clone());
                    scenario_idx += 1;
                }
            }

            let burst = sim.is_burst();
            if let Some(event) = sim.next_event().await {
                packet_count += 1;
                handle_event(event, &engine, &traffic_tx, &stats).await;
                if packet_count.is_multiple_of(1000) {
                    info!("Processed {} simulated packets", packet_count);
                }
            }

            tokio::time::sleep(Duration::from_millis(if burst { 1 } else { sleep_ms })).await;
        }
    });
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
    let simulation_mode = env_flag("SIMULATION_MODE", true);
    let interface_name = std::env::var("CAPTURE_INTERFACE").unwrap_or_else(|_| "eth0".to_string());
    let stats = Arc::new(SensorStats::default());

    let pool = match database_url.as_deref() {
        Some(url) => connect_db(url).await,
        None => {
            warn!("DATABASE_URL not set: alerts and traffic will not be persisted");
            None
        }
    };

    // Alerts -> persistence
    let (alert_tx, alert_rx) = mpsc::channel::<Alert>(1000);
    spawn_alert_persister(alert_rx, pool.clone());

    // Traffic -> batched persistence + live stream (Mục 2)
    let (traffic_tx, traffic_rx) = mpsc::channel::<TrafficEvent>(5000);
    spawn_traffic_writer(traffic_rx, pool.clone(), stats.clone());

    let mut engine = DetectionEngine::new(alert_tx);

    // Automated response (Mục 17)
    if env_flag("AUTO_BLOCK_CRITICAL_IPS", true) {
        let (block_tx, block_rx) = mpsc::channel(256);
        engine.set_block_sender(block_tx);
        spawn_auto_blocker(block_rx, pool.clone());
    }
    if env_flag("FIREWALL_ENFORCEMENT", false) {
        match &pool {
            Some(p) => {
                info!("🔥 Firewall enforcement enabled: mirroring blocklist into iptables chain SECNET_BLOCK");
                spawn_firewall_sync(p.clone(), Duration::from_secs(30));
            }
            None => warn!("FIREWALL_ENFORCEMENT needs a database; ignored"),
        }
    }

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

    let engine = Arc::new(Mutex::new(engine));

    // Listen for rule changes in PostgreSQL to hot-reload in real-time (Mục 6)
    if let Some(ref p) = pool {
        spawn_rule_listener(p.clone(), engine.clone());
        spawn_heartbeat(p.clone(), interface_name.clone(), stats.clone());
    }

    // Periodic state snapshot (ARP bindings, volume baseline) and stale-state cleanup
    {
        let engine = engine.clone();
        let state_file = state_file.clone();
        tokio::spawn(async move {
            let mut snapshot = tokio::time::interval(Duration::from_secs(30));
            let mut cleanup = tokio::time::interval(Duration::from_secs(60));
            snapshot.tick().await;
            cleanup.tick().await;
            loop {
                tokio::select! {
                    _ = snapshot.tick() => {
                        if let Err(e) = engine.lock().await.save_state_to_file(&state_file) {
                            warn!("Periodic rule state snapshot failed: {}", e);
                        }
                    }
                    _ = cleanup.tick() => {
                        engine.lock().await.cleanup_stale_state(Duration::from_secs(300));
                    }
                }
            }
        });
    }

    let start_simulation = if simulation_mode {
        true
    } else {
        info!("Running in LIVE CAPTURE mode on interface '{}'", interface_name);
        let mut exclusions = Vec::new();
        if let Some(url) = database_url.as_deref() {
            exclusions.extend(service_endpoint(url, 5432).await);
        }
        if let Ok(url) = std::env::var("REDIS_URL") {
            exclusions.extend(service_endpoint(&url, 6379).await);
        }
        match LiveCapture::new(&interface_name, exclusions, stats.clone()) {
            Ok(mut live) => {
                let engine_live = engine.clone();
                let traffic_tx_live = traffic_tx.clone();
                let stats_live = stats.clone();
                tokio::spawn(async move {
                    while let Some(event) = live.next_event().await {
                        handle_event(event, &engine_live, &traffic_tx_live, &stats_live).await;
                    }
                    error!("Live capture stopped");
                    stats_live.mark_failed();
                });
                false
            }
            Err(e) => {
                error!("Could not start live capture on '{}': {}", interface_name, e);
                if env_flag("LIVE_FALLBACK_TO_SIMULATION", false) {
                    warn!("LIVE_FALLBACK_TO_SIMULATION=true: switching to simulated traffic");
                    true
                } else {
                    stats.mark_failed();
                    false
                }
            }
        }
    };

    if start_simulation {
        info!("Running in SIMULATION MODE on interface '{}'", interface_name);
        spawn_simulation(
            interface_name.clone(),
            engine.clone(),
            traffic_tx.clone(),
            stats.clone(),
        );
    }

    // Keep the main process running: Handle both SIGINT and SIGTERM (Mục 44)
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => info!("Received SIGINT signal, shutting down..."),
            _ = sigterm.recv() => info!("Received SIGTERM signal (e.g. docker stop), shutting down..."),
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
