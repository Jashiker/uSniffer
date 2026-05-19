use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

/// Parsed packet information
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub raw: Vec<u8>,
    pub time: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub length: usize,
    pub info: String,
}

impl ParsedPacket {
    pub fn new(
        raw: Vec<u8>,
        time: String,
        src_ip: String,
        dst_ip: String,
        protocol: String,
        length: usize,
        info: String,
    ) -> Self {
        Self {
            raw,
            time,
            src_ip,
            dst_ip,
            protocol,
            length,
            info,
        }
    }
}

/// Packet parser for different protocol layers
#[derive(Clone)]
pub struct PacketParser {
    protocol_config: crate::config::ProtocolConfig,
}

impl PacketParser {
    pub fn new(protocol_config: crate::config::ProtocolConfig) -> Self {
        Self { protocol_config }
    }

    /// Parse a raw packet into structured data
    pub fn parse_packet(&self, packet: &[u8], capture_time: &str) -> Option<ParsedPacket> {
        let raw = packet.to_vec();
        let length = packet.len();

        let ethernet = match EthernetPacket::new(packet) {
            Some(eth) => eth,
            None => return None,
        };

        match ethernet.get_ethertype() {
            EtherTypes::Arp => self.parse_arp_packet(&ethernet, &raw, capture_time, length),
            EtherTypes::Ipv4 => self.parse_ipv4_packet(&ethernet, &raw, capture_time, length),
            _ => None,
        }
    }

    fn parse_arp_packet(
        &self,
        ethernet: &EthernetPacket,
        raw: &[u8],
        capture_time: &str,
        length: usize,
    ) -> Option<ParsedPacket> {
        let arp_packet = match ArpPacket::new(ethernet.payload()) {
            Some(arp) => arp,
            None => return None,
        };

        Some(ParsedPacket::new(
            raw.to_vec(),
            capture_time.to_string(),
            arp_packet.get_sender_proto_addr().to_string(),
            arp_packet.get_target_proto_addr().to_string(),
            "ARP".to_string(),
            length,
            format!(
                "{}->{}",
                arp_packet.get_sender_hw_addr(),
                arp_packet.get_target_hw_addr()
            ),
        ))
    }

    fn parse_ipv4_packet(
        &self,
        ethernet: &EthernetPacket,
        raw: &[u8],
        capture_time: &str,
        length: usize,
    ) -> Option<ParsedPacket> {
        let ipv4_packet = match Ipv4Packet::new(ethernet.payload()) {
            Some(ipv4) => ipv4,
            None => return None,
        };

        let src_ip = ipv4_packet.get_source().to_string();
        let dst_ip = ipv4_packet.get_destination().to_string();

        let (protocol, info) = self.parse_transport_protocol(&ipv4_packet)?;

        Some(ParsedPacket::new(
            raw.to_vec(),
            capture_time.to_string(),
            src_ip,
            dst_ip,
            protocol,
            length,
            info,
        ))
    }

    fn parse_transport_protocol(&self, ipv4_packet: &Ipv4Packet) -> Option<(String, String)> {
        let src_ip = ipv4_packet.get_source();
        let dst_ip = ipv4_packet.get_destination();

        match ipv4_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                self.parse_tcp_protocol(ipv4_packet.payload(), &src_ip, &dst_ip)
            }
            IpNextHeaderProtocols::Udp => {
                self.parse_udp_protocol(ipv4_packet.payload(), &src_ip, &dst_ip)
            }
            IpNextHeaderProtocols::Icmp => {
                self.parse_icmp_protocol(ipv4_packet.payload())
            }
            _ => Some(("Other".to_string(), self.get_ipv4_info(ipv4_packet))),
        }
    }

    fn parse_tcp_protocol(
        &self,
        payload: &[u8],
        src_ip: &std::net::Ipv4Addr,
        dst_ip: &std::net::Ipv4Addr,
    ) -> Option<(String, String)> {
        let tcp = match TcpPacket::new(payload) {
            Some(tcp) => tcp,
            None => return None,
        };

        let src_port = tcp.get_source();
        let dst_port = tcp.get_destination();

        // Determine protocol name based on ports
        let protocol = if let Some(proto) = self.protocol_config.get_protocol_by_port(dst_port, true) {
            proto.to_string()
        } else if let Some(proto) = self.protocol_config.get_protocol_by_port(src_port, true) {
            proto.to_string()
        } else {
            "TCP".to_string()
        };

        let info = format!(
            "{}->{} ,Flags: {}, Seq: {}, Ack: {}",
            src_port,
            dst_port,
            tcp.get_flags(),
            tcp.get_sequence(),
            tcp.get_acknowledgement(),
        );

        Some((protocol, info))
    }

    fn parse_udp_protocol(
        &self,
        payload: &[u8],
        src_ip: &std::net::Ipv4Addr,
        dst_ip: &std::net::Ipv4Addr,
    ) -> Option<(String, String)> {
        let udp = match UdpPacket::new(payload) {
            Some(udp) => udp,
            None => return None,
        };

        let src_port = udp.get_source();
        let dst_port = udp.get_destination();

        // Determine protocol name based on ports
        let protocol = if let Some(proto) = self.protocol_config.get_protocol_by_port(dst_port, false) {
            proto.to_string()
        } else if let Some(proto) = self.protocol_config.get_protocol_by_port(src_port, false) {
            proto.to_string()
        } else {
            "UDP".to_string()
        };

        let info = format!("{}->{} ,Length: {}", src_port, dst_port, udp.get_length());

        Some((protocol, info))
    }

    fn parse_icmp_protocol(&self, payload: &[u8]) -> Option<(String, String)> {
        let icmp = match IcmpPacket::new(payload) {
            Some(icmp) => icmp,
            None => return None,
        };

        let info = format!(
            "Type: {:?}, Code: {:?}",
            icmp.get_icmp_type(),
            icmp.get_icmp_code()
        );

        Some(("ICMP".to_string(), info))
    }

    fn get_ipv4_info(&self, ipv4_packet: &Ipv4Packet) -> String {
        format!(
            "TTL: {}, DF: {}, MF: {}",
            ipv4_packet.get_ttl(),
            if ipv4_packet.get_flags() & 0x2 != 0 { "Yes" } else { "No" },
            if ipv4_packet.get_flags() & 0x1 != 0 { "Yes" } else { "No" }
        )
    }
}

impl Default for PacketParser {
    fn default() -> Self {
        Self::new(crate::config::ProtocolConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parsed_packet_creation() {
        let packet = ParsedPacket::new(
            vec![1, 2, 3],
            "12:00:00".to_string(),
            "192.168.1.1".to_string(),
            "192.168.1.2".to_string(),
            "TCP".to_string(),
            64,
            "80->443".to_string(),
        );

        assert_eq!(packet.protocol, "TCP");
        assert_eq!(packet.length, 64);
        assert_eq!(packet.info, "80->443");
    }
}
