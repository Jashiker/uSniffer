use std::collections::HashMap;

/// Protocol configuration mapping well-known ports to protocol names
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    pub tcp_ports: HashMap<u16, &'static str>,
    pub udp_ports: HashMap<u16, &'static str>,
}

impl ProtocolConfig {
    pub fn new() -> Self {
        let mut tcp_ports = HashMap::new();
        let mut udp_ports = HashMap::new();

        // TCP ports
        tcp_ports.insert(80, "HTTP");
        tcp_ports.insert(443, "HTTPS");
        tcp_ports.insert(53, "DNS");
        tcp_ports.insert(21, "FTP");
        tcp_ports.insert(22, "SSH");
        tcp_ports.insert(23, "Telnet");
        tcp_ports.insert(25, "SMTP");
        tcp_ports.insert(110, "POP3");
        tcp_ports.insert(143, "IMAP");
        tcp_ports.insert(3389, "RDP");
        tcp_ports.insert(5060, "SIP");
        tcp_ports.insert(8080, "HTTP"); // Alternative HTTP port

        // UDP ports
        udp_ports.insert(80, "HTTP");
        udp_ports.insert(443, "HTTPS");
        udp_ports.insert(53, "DNS");
        udp_ports.insert(21, "FTP");
        udp_ports.insert(22, "SSH");
        udp_ports.insert(23, "Telnet");
        udp_ports.insert(25, "SMTP");
        udp_ports.insert(110, "POP3");
        udp_ports.insert(143, "IMAP");
        udp_ports.insert(3389, "RDP");
        udp_ports.insert(5060, "SIP");
        udp_ports.insert(8080, "HTTP"); // Alternative HTTP port

        Self {
            tcp_ports,
            udp_ports,
        }
    }

    pub fn get_protocol_by_port(&self, port: u16, is_tcp: bool) -> Option<&'static str> {
        if is_tcp {
            self.tcp_ports.get(&port).copied()
        } else {
            self.udp_ports.get(&port).copied()
        }
    }
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct SnifferConfig {
    pub window_size: [f32; 2],
    pub transparent: bool,
    pub protocol_config: ProtocolConfig,
    pub traffic_history_limit: usize,
    pub tcp_stream_display_limit: usize,
}

impl Default for SnifferConfig {
    fn default() -> Self {
        Self {
            window_size: [1000.0, 750.0],
            transparent: true,
            protocol_config: ProtocolConfig::default(),
            traffic_history_limit: 60,
            tcp_stream_display_limit: 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_config_tcp() {
        let config = ProtocolConfig::new();
        assert_eq!(config.get_protocol_by_port(80, true), Some("HTTP"));
        assert_eq!(config.get_protocol_by_port(443, true), Some("HTTPS"));
        assert_eq!(config.get_protocol_by_port(22, true), Some("SSH"));
    }

    #[test]
    fn test_protocol_config_udp() {
        let config = ProtocolConfig::new();
        assert_eq!(config.get_protocol_by_port(53, false), Some("DNS"));
        assert_eq!(config.get_protocol_by_port(123, false), None); // NTP not configured
    }
}
