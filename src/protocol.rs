use std::collections::HashMap;

/// TCP flags constants
pub const TH_FIN: u8 = 0x01; // 结束连接
pub const TH_SYN: u8 = 0x02; // 同步序列号
pub const TH_RST: u8 = 0x04; // 重置连接
pub const TH_PSH: u8 = 0x08; // 推送
pub const TH_ACK: u8 = 0x10; // 确认
pub const TH_URG: u8 = 0x20; // 紧急
pub const TH_ECE: u8 = 0x40; // ECN回显
pub const TH_CWR: u8 = 0x80; // 拥塞窗口减少

/// TCP stream information
#[derive(Debug, Clone)]
pub struct TcpStream {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub packets: Vec<crate::packet::ParsedPacket>,
    pub last_activity: String,
    pub handshake_complete: bool,
    pub teardown_started: bool,
}

impl TcpStream {
    pub fn new(
        src_ip: String,
        src_port: u16,
        dst_ip: String,
        dst_port: u16,
        first_packet: crate::packet::ParsedPacket,
        capture_time: String,
    ) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            packets: vec![first_packet],
            last_activity: capture_time,
            handshake_complete: false,
            teardown_started: false,
        }
    }

    pub fn add_packet(&mut self, packet: crate::packet::ParsedPacket, capture_time: String) {
        self.packets.push(packet);
        self.last_activity = capture_time;
    }

    pub fn update_handshake_status(&mut self, flags_value: u8) {
        if Self::is_syn_packet(flags_value) || Self::is_syn_ack_packet(flags_value) {
            self.handshake_complete = false;
        } else if Self::is_ack_packet(flags_value) && !self.handshake_complete {
            // 第三次握手完成
            self.handshake_complete = true;
        } else if Self::is_fin_packet(flags_value) {
            self.teardown_started = true;
        }
    }

    pub fn is_syn_packet(flags_value: u8) -> bool {
        (flags_value & TH_SYN != 0) && (flags_value & TH_ACK == 0)
    }

    pub fn is_syn_ack_packet(flags_value: u8) -> bool {
        (flags_value & TH_SYN != 0) && (flags_value & TH_ACK != 0)
    }

    pub fn is_ack_packet(flags_value: u8) -> bool {
        (flags_value & TH_ACK != 0) && (flags_value & TH_SYN == 0) && (flags_value & TH_FIN == 0)
    }

    pub fn is_fin_packet(flags_value: u8) -> bool {
        flags_value & TH_FIN != 0
    }

    pub fn is_control_packet(info: &str) -> bool {
        info.contains("Flags:")
    }

    pub fn extract_flags_value(info: &str) -> u8 {
        if let Some(flags_start) = info.find("Flags: ") {
            let flags_part = &info[flags_start + 7..];
            if let Some(comma_pos) = flags_part.find(|c| c == ',' || c == ' ') {
                let flags_str = &flags_part[..comma_pos];
                if let Ok(flags_value) = flags_str.parse::<u8>() {
                    return flags_value;
                }
            } else {
                if let Ok(flags_value) = flags_part.parse::<u8>() {
                    return flags_value;
                }
            }
        }
        0
    }

    pub fn parse_flags(flags_value: u8) -> String {
        let mut flags = Vec::new();

        if flags_value & TH_FIN != 0 {
            flags.push("FIN");
        }
        if flags_value & TH_SYN != 0 {
            flags.push("SYN");
        }
        if flags_value & TH_RST != 0 {
            flags.push("RST");
        }
        if flags_value & TH_PSH != 0 {
            flags.push("PSH");
        }
        if flags_value & TH_ACK != 0 {
            flags.push("ACK");
        }
        if flags_value & TH_URG != 0 {
            flags.push("URG");
        }
        if flags_value & TH_ECE != 0 {
            flags.push("ECE");
        }
        if flags_value & TH_CWR != 0 {
            flags.push("CWR");
        }

        if flags.is_empty() {
            format!("0x{:02x}", flags_value)
        } else {
            flags.join(",")
        }
    }
}

/// TCP stream manager for tracking multiple streams
pub struct TcpStreamManager {
    streams: HashMap<String, TcpStream>,
}

impl TcpStreamManager {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    pub fn add_or_update_stream(
        &mut self,
        packet: &crate::packet::ParsedPacket,
        capture_time: String,
    ) {
        // Extract port information from packet info
        if let Some(arrow_pos) = packet.info.find("->") {
            if let Some(comma_pos) = packet.info[arrow_pos..].find(" ,") {
                let src_port_str = &packet.info[..arrow_pos];
                let dst_port_str = &packet.info[arrow_pos + 2..arrow_pos + comma_pos];

                if let (Ok(src_port), Ok(dst_port)) = (
                    src_port_str.parse::<u16>(),
                    dst_port_str.parse::<u16>(),
                ) {
                    let stream_key = Self::generate_stream_key(
                        &packet.src_ip,
                        src_port,
                        &packet.dst_ip,
                        dst_port,
                    );

                    self.streams
                        .entry(stream_key.clone())
                        .and_modify(|stream| {
                            stream.add_packet(packet.clone(), capture_time.clone());
                            if TcpStream::is_control_packet(&packet.info) {
                                let flags_value = TcpStream::extract_flags_value(&packet.info);
                                stream.update_handshake_status(flags_value);
                            }
                        })
                        .or_insert_with(|| {
                            let mut stream = TcpStream::new(
                                packet.src_ip.clone(),
                                src_port,
                                packet.dst_ip.clone(),
                                dst_port,
                                packet.clone(),
                                capture_time.clone(),
                            );

                            if TcpStream::is_control_packet(&packet.info) {
                                let flags_value = TcpStream::extract_flags_value(&packet.info);
                                if TcpStream::is_ack_packet(flags_value) {
                                    // 如果第一个包就是ACK包，可能已经完成握手
                                    stream.handshake_complete = true;
                                }
                            }

                            stream
                        });
                }
            }
        }
    }

    pub fn get_streams(&self) -> &HashMap<String, TcpStream> {
        &self.streams
    }

    pub fn get_complete_streams(&self, limit: usize) -> Vec<(&String, &TcpStream)> {
        let mut streams: Vec<(&String, &TcpStream)> = self.streams
            .iter()
            .filter(|(_, stream)| stream.handshake_complete && stream.teardown_started)
            .collect();

        // Sort by last activity (most recent first)
        streams.sort_by(|a, b| b.1.last_activity.cmp(&a.1.last_activity));

        streams.into_iter().take(limit).collect()
    }

    pub fn clear(&mut self) {
        self.streams.clear();
    }

    fn generate_stream_key(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> String {
        if src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port) {
            format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port)
        } else {
            format!("{}:{}-{}:{}", dst_ip, dst_port, src_ip, src_port)
        }
    }
}

impl Default for TcpStreamManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Protocol analyzer for traffic statistics
pub struct ProtocolAnalyzer {
    current_traffic: HashMap<String, usize>,
    traffic_history: Vec<(u64, HashMap<String, usize>)>,
    last_update_time: u64,
    history_limit: usize,
}

impl ProtocolAnalyzer {
    pub fn new(history_limit: usize) -> Self {
        Self {
            current_traffic: HashMap::new(),
            traffic_history: Vec::new(),
            last_update_time: chrono::Utc::now().timestamp() as u64,
            history_limit,
        }
    }

    pub fn add_packet(&mut self, protocol: &str, length: usize) {
        *self.current_traffic.entry(protocol.to_string()).or_insert(0) += length;

        let current_time = chrono::Utc::now().timestamp() as u64;
        if current_time - self.last_update_time >= 1 {
            // Update every second
            self.traffic_history.push((self.last_update_time, self.current_traffic.clone()));
            if self.traffic_history.len() > self.history_limit {
                self.traffic_history.remove(0);
            }
            self.current_traffic.clear();
            self.last_update_time = current_time;
        }
    }

    pub fn get_current_traffic(&self) -> &HashMap<String, usize> {
        &self.current_traffic
    }

    pub fn get_traffic_history(&self) -> &Vec<(u64, HashMap<String, usize>)> {
        &self.traffic_history
    }

    pub fn get_accumulated_traffic(&self) -> HashMap<String, usize> {
        let mut accumulated = HashMap::new();

        for (_, traffic_map) in &self.traffic_history {
            for (protocol, traffic) in traffic_map {
                *accumulated.entry(protocol.clone()).or_insert(0) += traffic;
            }
        }

        for (protocol, traffic) in &self.current_traffic {
            *accumulated.entry(protocol.clone()).or_insert(0) += traffic;
        }

        accumulated
    }

    pub fn clear(&mut self) {
        self.current_traffic.clear();
        self.traffic_history.clear();
        self.last_update_time = chrono::Utc::now().timestamp() as u64;
    }
}

impl Default for ProtocolAnalyzer {
    fn default() -> Self {
        Self::new(60) // Default 60 seconds history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_stream_creation() {
        let packet = crate::packet::ParsedPacket::new(
            vec![1, 2, 3],
            "12:00:00".to_string(),
            "192.168.1.1".to_string(),
            "192.168.1.2".to_string(),
            "TCP".to_string(),
            64,
            "12345->80 ,Flags: 2".to_string(),
        );

        let stream = TcpStream::new(
            "192.168.1.1".to_string(),
            12345,
            "192.168.1.2".to_string(),
            80,
            packet,
            "12:00:00".to_string(),
        );

        assert_eq!(stream.src_ip, "192.168.1.1");
        assert_eq!(stream.src_port, 12345);
        assert_eq!(stream.dst_ip, "192.168.1.2");
        assert_eq!(stream.dst_port, 80);
        assert_eq!(stream.packets.len(), 1);
    }

    #[test]
    fn test_tcp_flags_parsing() {
        assert!(TcpStream::is_syn_packet(TH_SYN));
        assert!(!TcpStream::is_syn_packet(TH_ACK));
        assert!(TcpStream::is_syn_ack_packet(TH_SYN | TH_ACK));
        assert!(TcpStream::is_ack_packet(TH_ACK));
        assert!(TcpStream::is_fin_packet(TH_FIN));

        let flags_str = TcpStream::parse_flags(TH_SYN | TH_ACK);
        assert!(flags_str.contains("SYN"));
        assert!(flags_str.contains("ACK"));
    }

    #[test]
    fn test_protocol_analyzer() {
        let mut analyzer = ProtocolAnalyzer::new(10);
        analyzer.add_packet("TCP", 100);
        analyzer.add_packet("UDP", 50);
        analyzer.add_packet("TCP", 75);

        let current = analyzer.get_current_traffic();
        assert_eq!(current.get("TCP"), Some(&175));
        assert_eq!(current.get("UDP"), Some(&50));
    }
}
