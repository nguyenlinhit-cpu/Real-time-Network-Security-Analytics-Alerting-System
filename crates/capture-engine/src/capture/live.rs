use chrono::Utc;
use common::models::TrafficEvent;
use ipnetwork::IpNetwork;
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::thread;
use tokio::sync::mpsc::{channel, Receiver};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::PacketSource;

pub struct LiveCapture {
    pub interface_name: String,
    receiver: Mutex<Receiver<TrafficEvent>>,
}

impl LiveCapture {
    pub fn new(interface_name: &str) -> Result<Self, String> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface: &NetworkInterface| iface.name == interface_name)
            .ok_or_else(|| format!("Network interface '{}' not found", interface_name))?;

        let (tx, rx) = channel::<TrafficEvent>(10000);
        let iface_name = interface_name.to_string();

        thread::spawn(move || {
            let (_, mut rx_channel) = match datalink::channel(&interface, Default::default()) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => {
                    error!("Unhandled channel type on interface {}", iface_name);
                    return;
                }
                Err(e) => {
                    warn!("Failed to create datalink channel (requires root/CAP_NET_RAW): {}. Fallback to simulated mode recommended.", e);
                    return;
                }
            };

            info!("Live packet capture started on interface {}", iface_name);

            loop {
                match rx_channel.next() {
                    Ok(packet) => {
                        if let Some(event) = Self::parse_ethernet_frame(packet, &iface_name) {
                            if tx.blocking_send(event).is_err() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Error reading packet: {}", e);
                    }
                }
            }
        });

        Ok(Self {
            interface_name: interface_name.to_string(),
            receiver: Mutex::new(rx),
        })
    }

    /// Extract DNS query domain from UDP payload (offset 12 is question section)
    fn parse_dns_query_domain(data: &[u8]) -> Option<String> {
        if data.len() < 13 {
            return None;
        }
        let mut offset = 12; // Skip 12-byte DNS header
        let mut labels = Vec::new();
        while offset < data.len() {
            let len = data[offset] as usize;
            if len == 0 {
                break;
            }
            if len >= 64 || offset + 1 + len > data.len() {
                return None;
            }
            offset += 1;
            let label = std::str::from_utf8(&data[offset..offset + len]).ok()?;
            labels.push(label);
            offset += len;
        }
        if labels.is_empty() {
            None
        } else {
            Some(labels.join("."))
        }
    }

    fn parse_ethernet_frame(packet: &[u8], iface: &str) -> Option<TrafficEvent> {
        let eth = EthernetPacket::new(packet)?;
        let eth_payload = eth.payload();

        // 1. Support ARP Packet Parsing (Mục 3)
        if eth.get_ethertype() == EtherTypes::Arp {
            if let Some(arp) = ArpPacket::new(eth_payload) {
                let src =
                    IpNetwork::new(std::net::IpAddr::V4(arp.get_sender_proto_addr()), 32).ok()?;
                let dst =
                    IpNetwork::new(std::net::IpAddr::V4(arp.get_target_proto_addr()), 32).ok()?;
                return Some(TrafficEvent {
                    time: Utc::now(),
                    id: Uuid::new_v4(),
                    src_ip: src,
                    dst_ip: dst,
                    src_port: 0,
                    dst_port: 0,
                    protocol: "ARP".to_string(),
                    bytes_transferred: packet.len() as i64,
                    packet_count: 1,
                    flags: format!("MAC:{}", arp.get_sender_hw_addr()),
                    interface_name: iface.to_string(),
                });
            }
            return None;
        }

        let (src_ip, dst_ip, next_protocol, l4_payload) = match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ip = Ipv4Packet::new(eth_payload)?;
                let src = IpNetwork::new(std::net::IpAddr::V4(ip.get_source()), 32).ok()?;
                let dst = IpNetwork::new(std::net::IpAddr::V4(ip.get_destination()), 32).ok()?;
                let header_len = (ip.get_header_length() as usize) * 4;
                if eth_payload.len() < header_len {
                    return None;
                }
                (
                    src,
                    dst,
                    ip.get_next_level_protocol(),
                    &eth_payload[header_len..],
                )
            }
            EtherTypes::Ipv6 => {
                let ip = Ipv6Packet::new(eth_payload)?;
                let src = IpNetwork::new(std::net::IpAddr::V6(ip.get_source()), 128).ok()?;
                let dst = IpNetwork::new(std::net::IpAddr::V6(ip.get_destination()), 128).ok()?;
                if eth_payload.len() < 40 {
                    return None;
                }
                (src, dst, ip.get_next_header(), &eth_payload[40..])
            }
            _ => return None,
        };

        let mut src_port = 0;
        let mut dst_port = 0;
        let mut protocol = "OTHER".to_string();
        let mut flags = String::new();

        match next_protocol {
            IpNextHeaderProtocols::Tcp => {
                protocol = "TCP".to_string();
                if let Some(tcp) = TcpPacket::new(l4_payload) {
                    src_port = tcp.get_source() as i32;
                    dst_port = tcp.get_destination() as i32;
                    let mut flag_list = Vec::new();
                    if tcp.get_flags() & 0x02 != 0 {
                        flag_list.push("SYN");
                    }
                    if tcp.get_flags() & 0x10 != 0 {
                        flag_list.push("ACK");
                    }
                    if tcp.get_flags() & 0x04 != 0 {
                        flag_list.push("RST");
                    }
                    if tcp.get_flags() & 0x01 != 0 {
                        flag_list.push("FIN");
                    }
                    if tcp.get_flags() & 0x08 != 0 {
                        flag_list.push("PSH");
                    }
                    flags = flag_list.join(",");
                }
            }
            IpNextHeaderProtocols::Udp => {
                protocol = "UDP".to_string();
                if let Some(udp) = UdpPacket::new(l4_payload) {
                    src_port = udp.get_source() as i32;
                    dst_port = udp.get_destination() as i32;

                    // 2. Support DNS Packet Parsing (Mục 3)
                    let udp_payload = udp.payload();
                    if (src_port == 53 || dst_port == 53) && udp_payload.len() > 12 {
                        if let Some(domain) = Self::parse_dns_query_domain(udp_payload) {
                            flags = format!("DNS:{}", domain);
                        }
                    }
                }
            }
            IpNextHeaderProtocols::Icmp => {
                protocol = "ICMP".to_string();
            }
            IpNextHeaderProtocols::Icmpv6 => {
                protocol = "ICMPv6".to_string();
            }
            _ => {}
        }

        // Ignore internal infrastructure traffic to avoid feedback loops (DB: 5432, Redis: 6379) (Mục C1.4)
        if src_port == 5432 || dst_port == 5432 || src_port == 6379 || dst_port == 6379 {
            return None;
        }

        Some(TrafficEvent {
            time: Utc::now(),
            id: Uuid::new_v4(),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            bytes_transferred: packet.len() as i64,
            packet_count: 1,
            flags,
            interface_name: iface.to_string(),
        })
    }
}

impl PacketSource for LiveCapture {
    async fn next_event(&mut self) -> Option<TrafficEvent> {
        let mut rx = self.receiver.lock().await;
        rx.recv().await
    }
}
