use chrono::Utc;
use common::models::TrafficEvent;
use ipnetwork::IpNetwork;
use rand::Rng;
use uuid::Uuid;

use super::PacketSource;

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
}

pub struct TrafficSimulator {
    interface_name: String,
    current_scenario: AttackScenario,
    scenario_step: usize,
}

impl TrafficSimulator {
    pub fn new(interface_name: String) -> Self {
        Self {
            interface_name,
            current_scenario: AttackScenario::None,
            scenario_step: 0,
        }
    }

    pub fn set_scenario(&mut self, scenario: AttackScenario) {
        self.current_scenario = scenario;
        self.scenario_step = 0;
    }

    pub fn generate_normal_event(&self) -> TrafficEvent {
        let mut rng = rand::thread_rng();

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
        let dst_ports = [80, 443, 53, 123, 8080];
        let protocols = ["TCP", "UDP", "TCP", "TCP"];

        let src_ip_str = src_ips[rng.gen_range(0..src_ips.len())];
        let dst_ip_str = dst_ips[rng.gen_range(0..dst_ips.len())];
        let port_idx = rng.gen_range(0..dst_ports.len());
        let dst_port = dst_ports[port_idx];
        let protocol = protocols[port_idx % protocols.len()].to_string();

        let src_port = rng.gen_range(49152..65535);
        let bytes_transferred = rng.gen_range(64..1500);

        TrafficEvent {
            time: Utc::now(),
            id: Uuid::new_v4(),
            src_ip: src_ip_str.parse().unwrap(),
            dst_ip: dst_ip_str.parse().unwrap(),
            src_port,
            dst_port,
            protocol,
            bytes_transferred,
            packet_count: 1,
            flags: if dst_port == 443 || dst_port == 80 {
                "ACK".to_string()
            } else {
                "".to_string()
            },
            interface_name: self.interface_name.clone(),
        }
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
                let attacker_ip: IpNetwork = "10.0.0.99/32".parse().unwrap();
                let port = start_port + (self.scenario_step as u16 % port_count);
                self.scenario_step += 1;

                Some(TrafficEvent {
                    time: Utc::now(),
                    id: Uuid::new_v4(),
                    src_ip: attacker_ip,
                    dst_ip: target_ip,
                    src_port: rng.gen_range(40000..60000),
                    dst_port: port as i32,
                    protocol: "TCP".to_string(),
                    bytes_transferred: 64,
                    packet_count: 1,
                    flags: "SYN".to_string(),
                    interface_name: self.interface_name.clone(),
                })
            }
            AttackScenario::SynFlood {
                target_ip,
                packet_count,
            } => {
                let attacker_ip: IpNetwork = "198.51.100.77/32".parse().unwrap();
                self.scenario_step += 1;
                if self.scenario_step > packet_count {
                    self.current_scenario = AttackScenario::None;
                }

                Some(TrafficEvent {
                    time: Utc::now(),
                    id: Uuid::new_v4(),
                    src_ip: attacker_ip,
                    dst_ip: target_ip,
                    src_port: rng.gen_range(1024..65535),
                    dst_port: 80,
                    protocol: "TCP".to_string(),
                    bytes_transferred: 40,
                    packet_count: 1,
                    flags: "SYN".to_string(),
                    interface_name: self.interface_name.clone(),
                })
            }
            AttackScenario::BruteForce {
                target_ip,
                port,
                attempts,
            } => {
                let attacker_ip: IpNetwork = "203.0.113.45/32".parse().unwrap();
                self.scenario_step += 1;
                if self.scenario_step > attempts {
                    self.current_scenario = AttackScenario::None;
                }

                Some(TrafficEvent {
                    time: Utc::now(),
                    id: Uuid::new_v4(),
                    src_ip: attacker_ip,
                    dst_ip: target_ip,
                    src_port: rng.gen_range(49152..65535),
                    dst_port: port as i32,
                    protocol: "TCP".to_string(),
                    bytes_transferred: 128,
                    packet_count: 3,
                    flags: "SYN,RST".to_string(),
                    interface_name: self.interface_name.clone(),
                })
            }
            AttackScenario::ArpSpoof {
                target_ip,
                fake_mac,
            } => {
                let attacker_ip: IpNetwork = "192.168.1.200/32".parse().unwrap();
                self.scenario_step += 1;

                Some(TrafficEvent {
                    time: Utc::now(),
                    id: Uuid::new_v4(),
                    src_ip: attacker_ip,
                    dst_ip: target_ip,
                    src_port: 0,
                    dst_port: 0,
                    protocol: "ARP".to_string(),
                    bytes_transferred: 42,
                    packet_count: 1,
                    flags: format!("MAC:{}", fake_mac),
                    interface_name: self.interface_name.clone(),
                })
            }
            AttackScenario::DnsTunneling { query_count } => {
                let attacker_ip: IpNetwork = "192.168.1.188/32".parse().unwrap();
                let dns_server: IpNetwork = "8.8.8.8/32".parse().unwrap();
                self.scenario_step += 1;
                if self.scenario_step > query_count {
                    self.current_scenario = AttackScenario::None;
                }

                let random_hex: String = (0..32)
                    .map(|_| format!("{:x}", rng.gen_range(0..16)))
                    .collect();
                let fake_domain = format!("{}.c2.tunnel-exfil.net", random_hex);

                Some(TrafficEvent {
                    time: Utc::now(),
                    id: Uuid::new_v4(),
                    src_ip: attacker_ip,
                    dst_ip: dns_server,
                    src_port: rng.gen_range(49152..65535),
                    dst_port: 53,
                    protocol: "UDP".to_string(),
                    bytes_transferred: 512,
                    packet_count: 1,
                    flags: format!("DNS:{}", fake_domain),
                    interface_name: self.interface_name.clone(),
                })
            }
            AttackScenario::TrafficVolumeSpike { multiplier } => {
                let normal = self.generate_normal_event();
                Some(TrafficEvent {
                    bytes_transferred: normal.bytes_transferred * (multiplier as i64),
                    packet_count: normal.packet_count * (multiplier as i32),
                    ..normal
                })
            }
        }
    }
}
