// Core modules
mod config;
mod network;
mod packet;
mod protocol;
mod ui;

// Re-exports for convenience
use chrono::prelude::Local;
use eframe::egui;
use pnet::datalink::NetworkInterface;
use std::sync::{Arc, Mutex};
use std::thread;

// Import our refactored modules
use config::SnifferConfig;
use network::{InterfaceManager, NetworkSniffer};
use packet::PacketParser;
use protocol::{ProtocolAnalyzer, TcpStreamManager};
use ui::{SnifferUI, UIState, AppState};

/// Main application struct - now much simpler and focused
struct SnifferApp {
    interface: NetworkInterface,
    current_state: AppState,
    promiscuous_mode: bool,

    // Core components
    ui: SnifferUI,
    packet_parser: PacketParser,
    network_sniffer: NetworkSniffer,
}

impl SnifferApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let config = SnifferConfig::default();
        let interface = InterfaceManager::get_interfaces()[0].clone();

        // Create shared state
        let ui_state = Arc::new(Mutex::new(UIState::new()));
        let protocol_analyzer = Arc::new(Mutex::new(ProtocolAnalyzer::new(config.traffic_history_limit)));
        let tcp_stream_manager = Arc::new(Mutex::new(TcpStreamManager::new()));

        // Create packet parser first (to avoid moving config)
        let packet_parser = PacketParser::new(config.protocol_config.clone());

        // Create UI component
        let ui = SnifferUI::new(
            config,
            Arc::clone(&ui_state),
            Arc::clone(&protocol_analyzer),
            Arc::clone(&tcp_stream_manager),
        );

        Self {
            interface: interface.clone(),
            current_state: AppState::Select,
            promiscuous_mode: true,
            ui,
            packet_parser,
            network_sniffer: NetworkSniffer::new(interface, true),
        }
    }

    fn show_interface_selection(&mut self, ctx: &egui::Context) {
        let interfaces = InterfaceManager::get_interfaces();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("Please Select A Interfaces To Sniff");
                ui.checkbox(&mut self.promiscuous_mode, "Promiscuous Mode");
                ui.add_space(10.0);

                for interface in interfaces {
                    if ui
                        .add_sized(
                            egui::Vec2::new(210.0, 30.0),
                            egui::Button::new(interface.name.clone()),
                        )
                        .clicked()
                    {
                        self.interface = interface;
                        self.current_state = AppState::Main;
                    }
                }
            })
        });
    }

    fn show_main_interface(&mut self, ctx: &egui::Context) {
        self.ui.show_main_interface(ctx);
    }

    fn start_sniffing(&mut self) {
        // Create shared state references for the packet handler
        let ui_state = self.ui.ui_state.clone();
        let protocol_analyzer = self.ui.protocol_analyzer.clone();
        let tcp_stream_manager = self.ui.tcp_stream_manager.clone();
        let packet_parser = self.packet_parser.clone();

        // Start sniffing with the packet handler
        if let Err(e) = self.network_sniffer.start_sniffing(move |packet_data| {
            let capture_time = Local::now().format("%H:%M:%S").to_string();

            // Parse packet
            if let Some(parsed_packet) = packet_parser.parse_packet(packet_data, &capture_time) {
                // Update UI state
                {
                    let mut ui_state_guard = ui_state.lock().unwrap();
                    ui_state_guard.packets.push(parsed_packet.clone());
                }

                // Update protocol analyzer
                {
                    let mut analyzer = protocol_analyzer.lock().unwrap();
                    analyzer.add_packet(&parsed_packet.protocol, parsed_packet.length);
                }

                // Update TCP stream manager for TCP packets
                if parsed_packet.protocol == "TCP"
                    || parsed_packet.protocol == "HTTP"
                    || parsed_packet.protocol == "HTTPS"
                    || parsed_packet.protocol == "FTP"
                    || parsed_packet.protocol == "SSH"
                    || parsed_packet.protocol == "Telnet"
                    || parsed_packet.protocol == "SMTP"
                    || parsed_packet.protocol == "POP3"
                    || parsed_packet.protocol == "IMAP"
                    || parsed_packet.protocol == "RDP"
                    || parsed_packet.protocol == "SIP"
                    || parsed_packet.protocol == "DNS"
                {
                    let mut stream_manager = tcp_stream_manager.lock().unwrap();
                    stream_manager.add_or_update_stream(&parsed_packet, capture_time);
                }
            }

            // Continue sniffing
            true
        }) {
            eprintln!("Failed to start sniffing: {}", e);
        }
    }

    fn stop_sniffing(&mut self) {
        // Update UI state to stop loading
        let mut ui_state = self.ui.ui_state.lock().unwrap();
        ui_state.loading = false;
        ui_state.clear();

        // Clear analyzers
        let mut analyzer = self.ui.protocol_analyzer.lock().unwrap();
        analyzer.clear();

        let mut stream_manager = self.ui.tcp_stream_manager.lock().unwrap();
        stream_manager.clear();
    }
}

impl eframe::App for SnifferApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        match self.current_state {
            AppState::Select => self.show_interface_selection(ctx),
            AppState::Main => {
                // Check if we should start sniffing
                let should_start = {
                    let ui_state = self.ui.ui_state.lock().unwrap();
                    ui_state.loading && !self.network_sniffer.is_sniffing()
                };

                if should_start {
                    self.start_sniffing();
                }

                // Check if we should stop sniffing
                let should_stop = {
                    let ui_state = self.ui.ui_state.lock().unwrap();
                    !ui_state.loading && self.network_sniffer.is_sniffing()
                };

                if should_stop {
                    self.network_sniffer.stop_sniffing();
                }

                self.show_main_interface(ctx);
            }
        }
    }
}

fn main() {
    let config = SnifferConfig::default();
    let mut options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([config.window_size[0], config.window_size[1]])
            .with_transparent(config.transparent),
        ..Default::default()
    };
    options.centered = true;

    let _ = eframe::run_native(
        "Sniffer",
        options,
        Box::new(|cc| Ok(Box::new(SnifferApp::new(cc)))),
    );
}
