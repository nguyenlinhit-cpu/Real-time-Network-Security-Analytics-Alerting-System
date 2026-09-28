use chrono::Utc;
use common::models::TrafficEvent;
use ipnetwork::IpNetwork;
use rand::Rng;
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::PacketSource;

pub const GATEWAY_IP: &str = "192.168.1.1/32";
pub const GATEWAY_MAC: &str = "00:1a:2b:3c:4d:01";

#[derive(Debug, Clone, PartialEq)]
pub enum AttackScenario {
    None,
    PortScan {
        target_ip: IpNetwork,
        start_port: u16,
        port_count: u16,
    },
    SynFlood {
        target_ip: IpNetwork,
        packet_count: usize,
    },
    BruteForce {
        target_ip: IpNetwork,
        port: u16,
        attempts: usize,
    },
    ArpSpoof {
        target_ip: IpNetwork,
        fake_mac: String,
    },
    DnsTunneling {
        query_count: usize,
    },
    TrafficVolumeSpike {
        multiplier: usize,
    },
    IcmpFlood {
        target_ip: IpNetwork,
        packet_count: usize,
    },
    Beaconing {
        c2_ip: IpNetwork,
        callbacks: usize,
        interval: Duration,
    },
}

impl AttackScenario {
    /// Builds a named demo scenario (`DEMO_SCENARIO` values).
    pub fn from_name(name: &str) -> Option<Self> {
        let target_ip: IpNetwork = "192.168.1.50/32".parse().expect("valid literal IP");
        Some(match name.to_lowercase().as_str() {
            "port_scan" => AttackScenario::PortScan {
                target_ip,
                start_port: 20,
                port_count: 30,
            },
            "syn_flood" => AttackScenario::SynFlood {
                target_ip,
                packet_count: 250,
            },
            "brute_force" => AttackScenario::BruteForce {
                target_ip,
                port: 22,
                attempts: 10,
            },
            "arp_spoof" => AttackScenario::ArpSpoof {
                target_ip: GATEWAY_IP.parse().expect("valid literal IP"),
                fake_mac: "de:ad:be:ef:00:01".to_string(),
            },
            "dns_tunnel" | "dns_tunneling" => AttackScenario::DnsTunneling { query_count: 15 },
            "volume_spike" => AttackScenario::TrafficVolumeSpike { multiplier: 20 },
            "icmp_flood" => AttackScenario::IcmpFlood {
                target_ip,
                packet_count: 120,
            },
            "beaconing" | "c2_beaconing" => AttackScenario::Beaconing {
                c2_ip: "185.220.101.4/32".parse().expect("valid literal IP"),
                callbacks: 10,
                interval: Duration::from_millis(1000),
            },
            _ => return None,
        })
    }

    /// Every scenario, in the order used by the `all` demo rotation.
    pub fn demo_rotation() -> Vec<(&'static str, Self)> {
        [
            "port_scan",
            "syn_flood",
            "brute_force",
            "arp_spoof",
            "dns_tunneling",
            "volume_spike",
            "icmp_flood",
            "beaconing",
        ]
        .iter()
        .filter_map(|n| Self::from_name(n).map(|s| (*n, s)))
        .collect()
    }
}

pub struct TrafficSimulator {
    interface_name: String,
    current_scenario: AttackScenario,
    scenario_step: usize,
    scenario_started: Instant,
    last_beacon: Option<Instant>,
}

impl TrafficSimulator {
    pub fn new(interface_name: String) -> Self {
        Self {
            interface_name,
            current_scenario: AttackScenario::None,
            scenario_step: 0,
            scenario_started: Instant::now(),
            last_beacon: None,
        }
    }

    pub fn set_scenario(&mut self, scenario: AttackScenario) {
        self.current_scenario = scenario;
        self.scenario_step = 0;
        self.scenario_started = Instant::now();
        self.last_beacon = None;
    }

    /// True when no attack scenario is running (only background traffic is produced).
    pub fn is_idle(&self) -> bool {
        self.current_scenario == AttackScenario::None
    }

    /// Flood-style scenarios should be replayed as fast as possible, like a real flood.
    pub fn is_burst(&self) -> bool {
        matches!(
            self.current_scenario,
            AttackScenario::SynFlood { .. }
                | AttackScenario::IcmpFlood { .. }
                | AttackScenario::PortScan { .. }
                | AttackScenario::TrafficVolumeSpike { .. }
        )
    }

    fn finish_after(&mut self, total: usize) {
        self.scenario_step += 1;
        if self.scenario_step >= total {
            self.current_scenario = AttackScenario::None;
        }
    }

    fn event(
        &self,
        src: IpNetwork,
        dst: IpNetwork,
        src_port: i32,
        dst_port: i32,
        protocol: &str,
        bytes: i64,
        packets: i32,
        flags: String,
    ) -> TrafficEvent {
        TrafficEvent {
            time: Utc::now(),
            id: Uuid::new_v4(),
            src_ip: src,
            dst_ip: dst,
            src_port,
            dst_port,
            protocol: protocol.to_string(),
            bytes_transferred: bytes,
            packet_count: packets,
            flags,
            interface_name: self.interface_name.clone(),
        }
    }

    pub fn generate_normal_event(&self) -> TrafficEvent {
        let mut rng = rand::thread_rng();

        // Occasional legitimate ARP announcement from the gateway, so the ARP detector learns
        // the real binding before any spoofing happens.
        if rng.gen_ratio(1, 40) {
            return self.event(
                GATEWAY_IP.parse().expect("valid literal IP"),
                "192.168.1.100/32".parse().expect("valid literal IP"),
                0,
                0,
                "ARP",
                42,
                1,
                format!("MAC:{}", GATEWAY_MAC),
            );
        }

        let src_ips = [
            "192.168.1.100/32",
            "192.168.1.101/32",
            "192.168.1.102/32",
            "192.168.1.105/32",
        ];
        let dst_ips = [
            "192.168.1.50/32",
            "1.1.1.1/32",
            "8.8.8.8/32",
            "142.250.190.46/32",
        ];
        // (dst_port, protocol, flags)
        let services: [(i32, &str, &str); 5] = [
            (80, "TCP", "ACK"),
            (443, "TCP", "PSH,ACK"),
            (53, "UDP", ""),
            (123, "UDP", ""),
            (8080, "TCP", "ACK"),
        ];

        let (dst_port, protocol, flags) = services[rng.gen_range(0..services.len())];
        let flags = if dst_port == 53 {
            let names = ["google.com", "github.com", "secnet.local", "ubuntu.com"];
            format!("DNS:{}", names[rng.gen_range(0..names.len())])
        } else {
            flags.to_string()
        };

        self.event(
            src_ips[rng.gen_range(0..src_ips.len())].parse().expect("valid literal IP"),
            dst_ips[rng.gen_range(0..dst_ips.len())].parse().expect("valid literal IP"),
            rng.gen_range(49152..65535),
            dst_port,
            protocol,
            rng.gen_range(64..1500),
            1,
            flags,
        )
    }
}

impl PacketSource for TrafficSimulator {
    async fn next_event(&mut self) -> Option<TrafficEvent> {
        let mut rng = rand::thread_rng();

        let scenario = self.current_scenario.clone();
        match scenario {
            AttackScenario::None => Some(self.generate_normal_event()),
            AttackScenario::PortScan {
                target_ip,
                start_port,
                port_count,
            } => {
                // One sequential pass over the port range, like a real scanner.
                let port = start_port + self.scenario_step as u16;
                self.finish_after(port_count as usize);
                Some(self.event(
                    "10.0.0.99/32".parse().expect("valid literal IP"),
                    target_ip,
                    rng.gen_range(40000..60000),
                    port as i32,
                    "TCP",
                    64,
                    1,
                    "SYN".to_string(),
                ))
            }
            AttackScenario::SynFlood {
                target_ip,
                packet_count,
            } => {
                self.finish_after(packet_count);
                Some(self.event(
                    "198.51.100.77/32".parse().expect("valid literal IP"),
                    target_ip,
                    rng.gen_range(1024..65535),
                    80,
                    "TCP",
                    40,
                    1,
                    "SYN".to_string(),
                ))
            }
            AttackScenario::BruteForce {
                target_ip,
                port,
                attempts,
            } => {
                self.finish_after(attempts);
                Some(self.event(
                    "203.0.113.45/32".parse().expect("valid literal IP"),
                    target_ip,
                    rng.gen_range(49152..65535),
                    port as i32,
                    "TCP",
                    128,
                    3,
                    "SYN,RST".to_string(),
                ))
            }
            AttackScenario::ArpSpoof {
                target_ip,
                fake_mac,
            } => {
                // The attacker (192.168.1.200) sends forged ARP replies claiming the gateway IP.
                self.finish_after(3);
                Some(self.event(
                    target_ip,
                    "192.168.1.100/32".parse().expect("valid literal IP"),
                    0,
                    0,
                    "ARP",
                    42,
                    1,
                    format!("MAC:{}", fake_mac),
                ))
            }
            AttackScenario::DnsTunneling { query_count } => {
                self.finish_after(query_count);
                // Base32/36-style encoded chunk, as produced by DNS tunnelling tools.
                const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
                let encoded: String = (0..48)
                    .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
                    .collect();
                Some(self.event(
                    "192.168.1.188/32".parse().expect("valid literal IP"),
                    "8.8.8.8/32".parse().expect("valid literal IP"),
                    rng.gen_range(49152..65535),
                    53,
                    "UDP",
                    512,
                    1,
                    format!("DNS:{}.c2.tunnel-exfil.net", encoded),
                ))
            }
            AttackScenario::TrafficVolumeSpike { multiplier } => {
                // ~2 seconds of bulk exfiltration-sized transfers from one host.
                if self.scenario_started.elapsed() >= Duration::from_secs(2) {
                    self.current_scenario = AttackScenario::None;
                }
                let bytes = rng.gen_range(1000..1500) * multiplier as i64;
                Some(self.event(
                    "192.168.1.105/32".parse().expect("valid literal IP"),
                    "142.250.190.46/32".parse().expect("valid literal IP"),
                    rng.gen_range(49152..65535),
                    443,
                    "TCP",
                    bytes,
                    multiplier as i32,
                    "PSH,ACK".to_string(),
                ))
            }
            AttackScenario::IcmpFlood {
                target_ip,
                packet_count,
            } => {
                self.finish_after(packet_count);
                Some(self.event(
                    "203.0.113.200/32".parse().expect("valid literal IP"),
                    target_ip,
                    0,
                    0,
                    "ICMP",
                    84,
                    1,
                    String::new(),
                ))
            }
            AttackScenario::Beaconing {
                c2_ip,
                callbacks,
                interval,
            } => {
                // Periodic callbacks with ~2% jitter, interleaved with normal traffic.
                let jitter = interval.mul_f64(rng.gen_range(-0.02..0.02f64).abs());
                let due = self
                    .last_beacon
                    .map(|t| t.elapsed() >= interval + jitter)
                    .unwrap_or(true);
                if !due {
                    return Some(self.generate_normal_event());
                }
                self.last_beacon = Some(Instant::now());
                self.finish_after(callbacks);
                Some(self.event(
                    "192.168.1.102/32".parse().expect("valid literal IP"),
                    c2_ip,
                    rng.gen_range(49152..65535),
                    8443,
                    "TCP",
                    74,
                    1,
                    "SYN".to_string(),
                ))
            }
        }
    }
}
