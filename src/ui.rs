use eframe::egui;
use egui_plot::{Line, Plot};
use std::sync::{Arc, Mutex};

use crate::config::SnifferConfig;
use crate::network::InterfaceManager;
use crate::packet::ParsedPacket;
use crate::protocol::{ProtocolAnalyzer, TcpStream, TcpStreamManager};

/// UI state management
#[derive(Debug, Clone)]
pub struct UIState {
    pub protocol_filter: String,
    pub ip_port_filter: String,
    pub port_filter: String,
    pub packets: Vec<ParsedPacket>,
    pub loading: bool,
}

impl UIState {
    pub fn new() -> Self {
        Self {
            protocol_filter: "All".to_string(),
            ip_port_filter: String::new(),
            port_filter: String::new(),
            packets: Vec::new(),
            loading: false,
        }
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.protocol_filter = "All".to_string();
        self.ip_port_filter.clear();
        self.port_filter.clear();
    }

    pub fn get_filtered_packets(&self) -> Vec<(usize, &ParsedPacket)> {
        self.packets
            .iter()
            .enumerate()
            .filter(|(_, packet)| {
                // Protocol filter
                if self.protocol_filter != "All"
                    && packet.protocol != self.protocol_filter
                {
                    return false;
                }

                // IP filter
                if !self.ip_port_filter.is_empty() {
                    let ip_filter = self.ip_port_filter.to_lowercase();
                    if !packet.src_ip.to_lowercase().contains(&ip_filter)
                        && !packet.dst_ip.to_lowercase().contains(&ip_filter)
                    {
                        return false;
                    }
                }

                // Port filter
                if !self.port_filter.is_empty() {
                    let port_filter = self.port_filter.to_lowercase();
                    if !packet.info.to_lowercase().contains(&port_filter) {
                        return false;
                    }
                }

                true
            })
            .collect()
    }
}

impl Default for UIState {
    fn default() -> Self {
        Self::new()
    }
}

/// Main UI renderer
pub struct SnifferUI {
    pub config: SnifferConfig,
    pub ui_state: Arc<Mutex<UIState>>,
    pub protocol_analyzer: Arc<Mutex<ProtocolAnalyzer>>,
    pub tcp_stream_manager: Arc<Mutex<TcpStreamManager>>,
}

impl SnifferUI {
    pub fn new(
        config: SnifferConfig,
        ui_state: Arc<Mutex<UIState>>,
        protocol_analyzer: Arc<Mutex<ProtocolAnalyzer>>,
        tcp_stream_manager: Arc<Mutex<TcpStreamManager>>,
    ) -> Self {
        Self {
            config,
            ui_state,
            protocol_analyzer,
            tcp_stream_manager,
        }
    }

    pub fn show_interface_selection(&self, current_interface: &mut pnet::datalink::NetworkInterface, current_state: &mut AppState) -> Vec<pnet::datalink::NetworkInterface> {
        let interfaces = InterfaceManager::get_interfaces();
        // This would be implemented with egui rendering
        interfaces
    }

    pub fn show_main_interface(&self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            self.show_menu_bar(ui);
            self.show_stats_panel(ui);
            self.show_packet_list(ui);
            self.show_protocol_stats(ui);
        });
    }

    fn show_menu_bar(&self, ui: &mut egui::Ui) {
        egui::TopBottomPanel::top("Menu")
            .min_height(60.0)
            .show_inside(ui, |ui| {
                ui.heading("Menu");

                ui.horizontal(|ui| {
                    let mut ui_state = self.ui_state.lock().unwrap();
                    if ui.button("▶ Start").clicked() && !ui_state.loading {
                        ui_state.loading = true;
                    }

                    if ui.button("⏸ Pause").clicked() {
                        ui_state.loading = false;
                    }

                    if ui.button("⏹ Stop").clicked() {
                        ui_state.loading = false;
                        ui_state.clear();

                        let mut analyzer = self.protocol_analyzer.lock().unwrap();
                        analyzer.clear();

                        let mut stream_manager = self.tcp_stream_manager.lock().unwrap();
                        stream_manager.clear();
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("Protocol: ");

                    let protocols = vec![
                        "All", "HTTP", "HTTPS", "FTP", "DNS", "SSH", "Telnet", "SMTP", "POP3",
                        "IMAP", "RDP", "SIP", "ICMP", "ARP",
                    ];

                    let mut ui_state = self.ui_state.lock().unwrap();
                    egui::ComboBox::from_label("")
                        .selected_text(&ui_state.protocol_filter)
                        .show_ui(ui, |ui| {
                            for protocol in &protocols {
                                let text = protocol.to_string();
                                ui.selectable_value(
                                    &mut ui_state.protocol_filter,
                                    text.clone(),
                                    text,
                                );
                            }
                        });

                    ui.label("IP Filter:");
                    ui.text_edit_singleline(&mut ui_state.ip_port_filter);

                    ui.label("Port Filter:");
                    ui.text_edit_singleline(&mut ui_state.port_filter);
                });
            });
    }

    fn show_stats_panel(&self, ui: &mut egui::Ui) {
        egui::SidePanel::right("Stats")
            .default_width(300.0)
            .min_width(300.0)
            .show_inside(ui, |ui| {
                self.show_tcp_streams(ui);
            });
    }

    fn show_tcp_streams(&self, ui: &mut egui::Ui) {
        ui.heading("TCP Streams");

        let stream_manager = self.tcp_stream_manager.lock().unwrap();
        let complete_streams = stream_manager.get_complete_streams(self.config.tcp_stream_display_limit);

        if complete_streams.is_empty() {
            ui.label("No complete TCP streams detected yet.");
            ui.label("Start sniffing to capture TCP traffic.");
        } else {
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (key, stream) in complete_streams {
                    self.show_tcp_stream(ui, key, stream);
                }
            });
        }
    }

    fn show_tcp_stream(&self, ui: &mut egui::Ui, key: &str, stream: &TcpStream) {
        egui::CollapsingHeader::new(format!("Stream: {}", key))
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Status:").strong());
                    if stream.handshake_complete && stream.teardown_started {
                        ui.label(egui::RichText::new("Complete").color(egui::Color32::GREEN));
                    } else if stream.handshake_complete {
                        ui.label(egui::RichText::new("Active").color(egui::Color32::YELLOW));
                    } else {
                        ui.label(egui::RichText::new("Connecting").color(egui::Color32::BLUE));
                    }
                });

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Packets:").strong());
                    ui.label(stream.packets.len().to_string());
                });

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Last activity:").strong());
                    ui.label(&stream.last_activity);
                });

                ui.add_space(5.0);
                ui.label(egui::RichText::new("Endpoints:").underline());
                ui.label(format!("  Source: {}:{}", stream.src_ip, stream.src_port));
                ui.label(format!("  Destination: {}:{}", stream.dst_ip, stream.dst_port));

                self.show_packet_sequence(ui, &stream.packets);
            });
    }

    fn show_packet_sequence(&self, ui: &mut egui::Ui, packets: &[ParsedPacket]) {
        ui.add_space(5.0);
        ui.label(egui::RichText::new("Complete packet sequence:").underline());

        for (i, packet) in packets.iter().enumerate() {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("[{}]", i + 1)).weak());
                    ui.label(egui::RichText::new(format!("[{}]", packet.time)).weak());
                    ui.label(format!("{} bytes", packet.length));
                });

                if TcpStream::is_control_packet(&packet.info) {
                    let flags_value = TcpStream::extract_flags_value(&packet.info);
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Raw Flags Value:").strong());
                        ui.label(format!("0x{:02x} ({})", flags_value, flags_value));
                    });

                    if let Some(flags_start) = packet.info.find("Flags: ") {
                        if let Some(flags_end) = packet.info[flags_start..].find(", Seq:") {
                            let flags_str = &packet.info[flags_start + 7..flags_start + flags_end];
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Extracted Flags String:").strong());
                                ui.label(flags_str);
                            });

                            if let Ok(parsed_flags) = flags_str.parse::<u8>() {
                                let flags = TcpStream::parse_flags(parsed_flags);
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Parsed Flags:").strong());
                                    ui.label(flags);
                                });
                            }
                        }
                    } else {
                        ui.label(&packet.info);
                    }
                }
            });
        }
    }

    fn show_packet_list(&self, ui: &mut egui::Ui) {
        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.heading("Network Traffic");

            let ui_state = self.ui_state.lock().unwrap();
            let filtered_packets = ui_state.get_filtered_packets();

            if !filtered_packets.is_empty() {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (index, packet) in filtered_packets.iter() {
                        self.show_packet_details(ui, index, packet);
                    }
                });
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("No packets captured. Click \"▶ Start\" to begin sniffing.");
                });
            }
        });
    }

    fn show_packet_details(&self, ui: &mut egui::Ui, index: &usize, packet: &ParsedPacket) {
        let header_text = self.build_packet_header_text(index, packet);

        let header_response = egui::CollapsingHeader::new(egui::RichText::new(header_text))
            .id_salt(index)
            .show(ui, |ui| {
                self.show_detailed_packet_info(ui, packet);
            });

        // Set background color based on protocol
        let protocol_color = self.get_protocol_color(&packet.protocol);
        let mut background_rect = header_response.header_response.rect;
        background_rect.extend_with_x(ui.clip_rect().right());
        ui.painter().rect_filled(
            background_rect,
            egui::CornerRadius::same(4),
            protocol_color,
        );

        ui.add_space(2.0);
    }

    fn build_packet_header_text(&self, index: &usize, packet: &ParsedPacket) -> String {
        let extra_info = self.get_protocol_specific_info(packet);

        format!(
            "No.{}:[{}]\t{} -> {}\t{}\t({} bytes)\t{}\t",
            index,
            packet.time,
            packet.src_ip,
            packet.dst_ip,
            packet.protocol,
            packet.length,
            extra_info,
        )
    }

    fn get_protocol_specific_info(&self, packet: &ParsedPacket) -> String {
        match packet.protocol.as_str() {
            "TCP" | "HTTP" | "HTTPS" | "FTP" | "SSH" | "Telnet" | "SMTP" | "POP3" | "IMAP" | "RDP" | "SIP" => {
                self.get_tcp_specific_info(packet)
            }
            "UDP" | "DNS" => self.get_udp_specific_info(packet),
            "ICMP" => self.get_icmp_specific_info(packet),
            "ARP" => self.get_arp_specific_info(packet),
            _ => String::new(),
        }
    }

    fn get_tcp_specific_info(&self, packet: &ParsedPacket) -> String {
        let mut info_parts = Vec::new();

        if let Some(arrow_pos) = packet.info.find("->") {
            if let Some(comma_pos) = packet.info[arrow_pos..].find(" ,") {
                let src_port = &packet.info[..arrow_pos];
                let dst_port = &packet.info[arrow_pos + 2..arrow_pos + comma_pos];
                info_parts.push(format!("{} -> {}", src_port, dst_port));
            }
        }

        if let Some(flags_start) = packet.info.find("Flags: ") {
            if let Some(flags_end) = packet.info[flags_start..].find(", Seq:") {
                let flags_str = &packet.info[flags_start + 7..flags_start + flags_end];
                if let Ok(flags_value) = flags_str.parse::<u8>() {
                    let mut flags = Vec::new();
                    if flags_value & crate::protocol::TH_SYN != 0 { flags.push("SYN"); }
                    if flags_value & crate::protocol::TH_ACK != 0 { flags.push("ACK"); }
                    if flags_value & crate::protocol::TH_FIN != 0 { flags.push("FIN"); }
                    if flags_value & crate::protocol::TH_RST != 0 { flags.push("RST"); }
                    if flags_value & crate::protocol::TH_PSH != 0 { flags.push("PSH"); }
                    if flags_value & crate::protocol::TH_URG != 0 { flags.push("URG"); }
                    if !flags.is_empty() {
                        info_parts.push(flags.join("|"));
                    }
                }
            }
        }

        if !info_parts.is_empty() {
            format!(" ({})", info_parts.join(", "))
        } else {
            String::new()
        }
    }

    fn get_udp_specific_info(&self, packet: &ParsedPacket) -> String {
        if let Some(arrow_pos) = packet.info.find("->") {
            if let Some(comma_pos) = packet.info[arrow_pos..].find(" ,") {
                let src_port = &packet.info[..arrow_pos];
                let dst_port = &packet.info[arrow_pos + 2..arrow_pos + comma_pos];
                return format!(" ({} -> {})", src_port, dst_port);
            }
        }
        String::new()
    }

    fn get_icmp_specific_info(&self, packet: &ParsedPacket) -> String {
        if packet.info.contains("Type:") && packet.info.contains("Code:") {
            if let Some(type_start) = packet.info.find("Type: ") {
                if let Some(code_start) = packet.info.find("Code: ") {
                    let type_info = &packet.info[type_start + 6..code_start].trim();
                    let code_info = &packet.info[code_start + 6..].trim();
                    return format!(" (Type: {}, Code: {})", type_info, code_info);
                }
            }
        }
        String::new()
    }

    fn get_arp_specific_info(&self, packet: &ParsedPacket) -> String {
        if let Some(arrow_pos) = packet.info.find("->") {
            let sender_hw = &packet.info[..arrow_pos];
            let target_hw = &packet.info[arrow_pos + 2..];
            format!(" ({} -> {})", sender_hw, target_hw)
        } else {
            String::new()
        }
    }

    fn show_detailed_packet_info(&self, ui: &mut egui::Ui, packet: &ParsedPacket) {
        ui.group(|ui| {
            // Basic info
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Time:").strong());
                ui.label(&packet.time);
            });

            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Source:").strong());
                ui.label(&packet.src_ip);
            });

            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Destination:").strong());
                ui.label(&packet.dst_ip);
            });

            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Protocol:").strong());
                ui.label(&packet.protocol);
            });

            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Length:").strong());
                ui.label(format!("{} bytes", packet.length));
            });

            // Protocol-specific details
            match packet.protocol.as_str() {
                "TCP" | "HTTP" | "HTTPS" | "FTP" | "SSH" | "Telnet" | "SMTP" | "POP3" | "IMAP" | "RDP" | "SIP" => {
                    self.show_tcp_details(ui, packet);
                }
                "UDP" | "DNS" => {
                    self.show_udp_details(ui, packet);
                }
                "ICMP" => {
                    self.show_icmp_details(ui, packet);
                }
                "ARP" => {
                    self.show_arp_details(ui, packet);
                }
                _ => {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Info:").strong());
                        ui.label(&packet.info);
                    });
                }
            }

            // Raw data
            self.show_raw_data(ui, &packet.raw);
        });
    }

    fn show_tcp_details(&self, ui: &mut egui::Ui, packet: &ParsedPacket) {
        ui.add_space(5.0);
        ui.separator();
        ui.label(egui::RichText::new("TCP Details:").strong());

        // Parse and display TCP flags
        if let Some(flags_start) = packet.info.find("Flags: ") {
            if let Some(flags_end) = packet.info[flags_start..].find(", Seq:") {
                let flags_str = &packet.info[flags_start + 7..flags_start + flags_end];
                if let Ok(flags_value) = flags_str.parse::<u8>() {
                    let flags = TcpStream::parse_flags(flags_value);
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Flags:").strong());
                        ui.label(flags);
                    });
                }
            }
        }

        // Display port information
        if let Some(arrow_pos) = packet.info.find("->") {
            if let Some(comma_pos) = packet.info[arrow_pos..].find(" ,") {
                let src_port = &packet.info[..arrow_pos];
                let dst_port = &packet.info[arrow_pos + 2..arrow_pos + comma_pos];
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Source Port:").strong());
                    ui.label(src_port);
                });
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Destination Port:").strong());
                    ui.label(dst_port);
                });
            }
        }
    }

    fn show_udp_details(&self, ui: &mut egui::Ui, packet: &ParsedPacket) {
        ui.add_space(5.0);
        ui.separator();
        ui.label(egui::RichText::new("UDP Details:").strong());

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Info:").strong());
            ui.label(&packet.info);
        });
    }

    fn show_icmp_details(&self, ui: &mut egui::Ui, packet: &ParsedPacket) {
        ui.add_space(5.0);
        ui.separator();
        ui.label(egui::RichText::new("ICMP Details:").strong());

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Info:").strong());
            ui.label(&packet.info);
        });
    }

    fn show_arp_details(&self, ui: &mut egui::Ui, packet: &ParsedPacket) {
        ui.add_space(5.0);
        ui.separator();
        ui.label(egui::RichText::new("ARP Details:").strong());

        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Info:").strong());
            ui.label(&packet.info);
        });
    }

    fn show_raw_data(&self, ui: &mut egui::Ui, raw_data: &[u8]) {
        ui.add_space(5.0);
        ui.separator();
        ui.label(egui::RichText::new("Raw Data:").strong());

        let mut hex_string = String::new();
        let mut ascii_string = String::new();

        for (i, byte) in raw_data.iter().enumerate() {
            if i % 16 == 0 && i > 0 {
                hex_string.push('\n');
                ascii_string.push('\n');
            }
            hex_string.push_str(&format!("{:02x} ", byte));

            let ascii_char = if *byte >= 32 && *byte <= 126 {
                *byte as char
            } else {
                '.'
            };
            ascii_string.push(ascii_char);
        }

        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label("Hex View:");
                ui.code(hex_string);
            });

            ui.add_space(5.0);

            ui.vertical(|ui| {
                ui.label("ASCII View:");
                ui.code(ascii_string);
            });
        });
    }

    fn show_protocol_stats(&self, ui: &mut egui::Ui) {
        egui::TopBottomPanel::bottom("Protocol")
            .min_height(200.0)
            .max_height(200.0)
            .show_inside(ui, |ui| {
                self.show_protocol_traffic_chart(ui);
            });
    }

    fn show_protocol_traffic_chart(&self, ui: &mut egui::Ui) {
        ui.heading("Protocol Traffic (Last 60s)");

        let analyzer = self.protocol_analyzer.lock().unwrap();

        if analyzer.get_traffic_history().is_empty() {
            ui.label("No traffic data yet. Start sniffing to see statistics.");
            return;
        }

        ui.horizontal(|ui| {
            self.show_traffic_plot(ui, &analyzer);
            ui.separator();
            self.show_protocol_distribution(ui, &analyzer);
        });
    }

    fn show_traffic_plot(&self, ui: &mut egui::Ui, analyzer: &ProtocolAnalyzer) {
        let protocols_to_plot = vec![
            "HTTP".to_string(), "HTTPS".to_string(), "TCP".to_string(),
            "UDP".to_string(), "ICMP".to_string(), "ARP".to_string(),
        ];

        let mut plot_data = Vec::new();
        for protocol in &protocols_to_plot {
            let mut points = Vec::new();
            for (i, (_, traffic_map)) in analyzer.get_traffic_history().iter().enumerate() {
                let traffic = traffic_map.get(protocol.as_str()).cloned().unwrap_or(0);
                points.push((i as f64, traffic as f64));
            }
            plot_data.push((protocol.clone(), points));
        }

        let plot = Plot::new("traffic_plot")
            .view_aspect(2.0)
            .height(180.0)
            .legend(egui_plot::Legend::default().position(egui_plot::Corner::RightBottom))
            .x_axis_label("Time (seconds)")
            .y_axis_label("Bytes");

        plot.show(ui, |plot_ui| {
            for (protocol, points) in &plot_data {
                let points_array: Vec<[f64; 2]> = points.iter().map(|&(x, y)| [x, y]).collect();
                let line = Line::new(protocol.clone(), points_array);
                plot_ui.line(line);
            }
        });
    }

    fn show_protocol_distribution(&self, ui: &mut egui::Ui, analyzer: &ProtocolAnalyzer) {
        ui.vertical(|ui| {
            ui.label(egui::RichText::new("Protocol Distribution").size(16.0).strong());

            let accumulated_traffic = analyzer.get_accumulated_traffic();
            let mut sorted_protocols: Vec<(String, usize)> = accumulated_traffic.into_iter().collect();
            sorted_protocols.sort_by(|a, b| b.1.cmp(&a.1));

            let total_traffic: usize = sorted_protocols.iter().map(|(_, traffic)| traffic).sum();
            let max_traffic = sorted_protocols.first().map(|(_, traffic)| *traffic).unwrap_or(0);

            if !sorted_protocols.is_empty() && max_traffic > 0 && total_traffic > 0 {
                self.show_bar_chart(ui, &sorted_protocols, max_traffic, total_traffic);
            } else {
                ui.label("No traffic data available");
                ui.label("Start capturing packets to see protocol distribution");
            }
        });
    }

    fn show_bar_chart(&self, ui: &mut egui::Ui, sorted_protocols: &[(String, usize)], max_traffic: usize, total_traffic: usize) {
        let bar_count = sorted_protocols.len().min(6);
        let bar_width = 25.0;
        let bar_spacing = 10.0;
        let chart_width = (bar_count as f32) * (bar_width + bar_spacing) + 80.0;
        let chart_height = 180.0;

        let (response, painter) = ui.allocate_painter(
            egui::Vec2::new(chart_width, chart_height),
            egui::Sense::hover(),
        );
        let rect = response.rect;

        let margin_left = 70.0;
        let margin_bottom = 25.0;
        let margin_top = 15.0;
        let margin_right = 5.0;

        let chart_rect = egui::Rect::from_min_max(
            egui::Pos2::new(rect.left() + margin_left, rect.top() + margin_top),
            egui::Pos2::new(rect.right() - margin_right, rect.bottom() - margin_bottom),
        );

        // Draw axes
        painter.line_segment(
            [
                egui::Pos2::new(chart_rect.left(), chart_rect.top()),
                egui::Pos2::new(chart_rect.left(), chart_rect.bottom()),
            ],
            egui::Stroke::new(1.0, egui::Color32::GRAY),
        );
        painter.line_segment(
            [
                egui::Pos2::new(chart_rect.left(), chart_rect.bottom()),
                egui::Pos2::new(chart_rect.right(), chart_rect.bottom()),
            ],
            egui::Stroke::new(1.0, egui::Color32::GRAY),
        );

        // Draw Y-axis labels
        let y_label_count = 5;
        for i in 0..=y_label_count {
            let y_value = (max_traffic as f64 * i as f64 / y_label_count as f64) as u32;
            let y_pos = chart_rect.bottom() - (i as f32 / y_label_count as f32) * chart_rect.height();

            if i > 0 && i < y_label_count {
                painter.line_segment(
                    [
                        egui::Pos2::new(chart_rect.left(), y_pos),
                        egui::Pos2::new(chart_rect.right(), y_pos),
                    ],
                    egui::Stroke::new(1.0, egui::Color32::DARK_GRAY),
                );
            }

            let text = format!("{}", y_value);
            painter.text(
                egui::Pos2::new(chart_rect.left() - 5.0, y_pos),
                egui::Align2::RIGHT_CENTER,
                text,
                egui::FontId::proportional(10.0),
                egui::Color32::GRAY,
            );
        }

        // Draw bars
        let colors = [
            egui::Color32::from_rgb(255, 99, 132),
            egui::Color32::from_rgb(54, 162, 235),
            egui::Color32::from_rgb(255, 205, 86),
            egui::Color32::from_rgb(75, 192, 192),
            egui::Color32::from_rgb(153, 102, 255),
            egui::Color32::from_rgb(255, 159, 64),
        ];

        for (i, (protocol, traffic)) in sorted_protocols.iter().take(6).enumerate() {
            if *traffic > 0 {
                let bar_height = (*traffic as f64 / max_traffic as f64 * chart_rect.height() as f64) as f32;
                let bar_left = chart_rect.left() + (i as f32) * (bar_width + bar_spacing) + bar_spacing / 2.0;
                let bar_right = bar_left + bar_width;
                let bar_top = chart_rect.bottom() - bar_height;

                let bar_rect = egui::Rect::from_min_max(
                    egui::Pos2::new(bar_left, bar_top),
                    egui::Pos2::new(bar_right, chart_rect.bottom()),
                );

                let color = colors[i % colors.len()];
                painter.rect_filled(bar_rect, 2.0, color);

                // Protocol name
                let text_pos = egui::Pos2::new(bar_left + bar_width / 2.0, chart_rect.bottom() + 5.0);
                painter.text(
                    text_pos,
                    egui::Align2::CENTER_TOP,
                    protocol,
                    egui::FontId::proportional(10.0),
                    egui::Color32::GRAY,
                );

                // Value on bar (if tall enough)
                if bar_height > 15.0 {
                    let value_text = format!("{}", traffic);
                    let value_pos = egui::Pos2::new(bar_left + bar_width / 2.0, bar_top + 3.0);
                    painter.text(
                        value_pos,
                        egui::Align2::CENTER_TOP,
                        value_text,
                        egui::FontId::proportional(9.0),
                        egui::Color32::WHITE,
                    );
                }
            }
        }

        // Axis labels
        painter.text(
            egui::Pos2::new(chart_rect.left() + chart_rect.width() / 2.0, chart_rect.bottom() + 20.0),
            egui::Align2::CENTER_CENTER,
            "Protocols",
            egui::FontId::proportional(11.0),
            egui::Color32::GRAY,
        );

        painter.text(
            egui::Pos2::new(chart_rect.left() - 25.0, chart_rect.top() + chart_rect.height() / 2.0),
            egui::Align2::CENTER_CENTER,
            "Bytes",
            egui::FontId::proportional(11.0),
            egui::Color32::GRAY,
        );

        // Summary
        ui.add_space(5.0);
        ui.label(egui::RichText::new(format!("Total Traffic: {} bytes", total_traffic)).size(12.0));

        // Protocol percentages
        ui.add_space(3.0);
        for (i, (protocol, traffic)) in sorted_protocols.iter().take(6).enumerate() {
            if *traffic > 0 {
                let percentage = (*traffic as f64 / total_traffic as f64) * 100.0;
                let color = colors[i % colors.len()];
                ui.horizontal(|ui| {
                    let (response, painter) = ui.allocate_painter(egui::Vec2::new(12.0, 12.0), egui::Sense::hover());
                    let rect = response.rect;
                    painter.rect_filled(rect, 0.0, color);
                    ui.label(format!("{}: {} bytes ({:.1}%)", protocol, traffic, percentage));
                });
            }
        }
    }

    fn get_protocol_color(&self, protocol: &str) -> egui::Color32 {
        match protocol {
            "TCP" => egui::Color32::from_rgba_premultiplied(40, 80, 160, 70),
            "UDP" => egui::Color32::from_rgba_premultiplied(160, 100, 40, 70),
            "ICMP" => egui::Color32::from_rgba_premultiplied(120, 40, 160, 70),
            "ARP" => egui::Color32::from_rgba_premultiplied(40, 140, 80, 70),
            "HTTP" => egui::Color32::from_rgba_premultiplied(180, 60, 80, 70),
            "HTTPS" => egui::Color32::from_rgba_premultiplied(40, 140, 140, 70),
            _ => egui::Color32::from_rgba_premultiplied(100, 100, 100, 70),
        }
    }
}

impl Default for SnifferUI {
    fn default() -> Self {
        Self::new(
            SnifferConfig::default(),
            Arc::new(Mutex::new(UIState::default())),
            Arc::new(Mutex::new(ProtocolAnalyzer::default())),
            Arc::new(Mutex::new(TcpStreamManager::default())),
        )
    }
}

/// Application state enum
#[derive(Debug, Clone, PartialEq)]
pub enum AppState {
    Select,
    Main,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ui_state_creation() {
        let ui_state = UIState::new();
        assert_eq!(ui_state.protocol_filter, "All");
        assert_eq!(ui_state.packets.len(), 0);
        assert!(!ui_state.loading);
    }

    #[test]
    fn test_ui_state_filtering() {
        let mut ui_state = UIState::new();

        let packet1 = ParsedPacket::new(
            vec![1, 2, 3],
            "12:00:00".to_string(),
            "192.168.1.1".to_string(),
            "192.168.1.2".to_string(),
            "TCP".to_string(),
            64,
            "80->443".to_string(),
        );

        let packet2 = ParsedPacket::new(
            vec![4, 5, 6],
            "12:00:01".to_string(),
            "192.168.1.3".to_string(),
            "192.168.1.4".to_string(),
            "UDP".to_string(),
            32,
            "53->12345".to_string(),
        );

        ui_state.packets.push(packet1);
        ui_state.packets.push(packet2);

        // Test protocol filter
        ui_state.protocol_filter = "TCP".to_string();
        let filtered = ui_state.get_filtered_packets();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].1.protocol, "TCP");

        // Test IP filter
        ui_state.protocol_filter = "All".to_string();
        ui_state.ip_port_filter = "192.168.1.3".to_string();
        let filtered = ui_state.get_filtered_packets();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].1.src_ip, "192.168.1.3");
    }
}
