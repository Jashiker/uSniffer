# uSniffer

A cross-platform network packet sniffer with a graphical user interface, written in Rust.

## Features

- **Real-time Packet Capture** — Capture live network traffic on any active interface
- **Protocol Identification** — Automatically identifies protocols by well-known ports: HTTP, HTTPS, FTP, SSH, Telnet, SMTP, POP3, IMAP, RDP, SIP, DNS, ICMP, ARP
- **Packet Filtering** — Filter captured packets by protocol, IP address, or port number
- **TCP Stream Tracking** — Tracks TCP connections including handshake/teardown status and full packet sequences
- **Traffic Statistics** — Real-time traffic plot and protocol distribution chart (last 60 seconds)
- **Promiscuous Mode** — Optional promiscuous mode for capturing all network traffic
- **Raw Data Viewer** — Hex and ASCII view of raw packet data

## Screenshots

![Interface Selection](docs/interface_selection.png)
![Packet Capture](docs/packet_capture.png)

## Architecture

```
src/
├── main.rs       # Application entry point and eframe app loop
├── config.rs     # Protocol port mappings and application configuration
├── network.rs    # Network interface discovery and packet capture thread
├── packet.rs     # Packet parsing (Ethernet / IPv4 / TCP / UDP / ICMP / ARP)
├── protocol.rs   # TCP stream manager and protocol traffic analyzer
└── ui.rs         # egui-based GUI rendering (menu, packet list, stats charts)
```

## Prerequisites

- **Rust** (edition 2024)
- **libpcap** development headers (required by the `pnet` crate)

### Installing libpcap

| OS | Command |
|---|---|
| Ubuntu / Debian | `sudo apt install libpcap-dev` |
| Fedora / RHEL | `sudo dnf install libpcap-devel` |
| Arch Linux | `sudo pacman -S libpcap` |
| macOS | Included with Xcode Command Line Tools |
| Windows | Install [Npcap SDK](https://nmap.org/npcap/) |

## Build & Run

```bash
# Build
cargo build --release

# Run (requires root/administrator privileges for packet capture)
sudo ./target/release/sniffer
```

> On Linux/macOS, raw socket access requires root privileges. Run with `sudo`.

## Usage

1. **Select Interface** — On launch, choose a network interface from the list and optionally toggle promiscuous mode
2. **Start Capture** — Click the **▶ Start** button to begin capturing packets
3. **Filter Traffic** — Use the protocol dropdown, IP filter, or port filter to narrow results
4. **Inspect Packets** — Click on any packet to expand detailed information including raw hex/ASCII data
5. **View Statistics** — The bottom panel shows real-time traffic trends and protocol distribution
6. **Stop / Pause** — Use **⏸ Pause** or **⏹ Stop** to control capture

## Dependencies

| Crate | Purpose |
|---|---|
| [`pnet`](https://crates.io/crates/pnet) | Low-level network packet capture and parsing |
| [`eframe`](https://crates.io/crates/eframe) / [`egui`](https://crates.io/crates/egui) | Immediate-mode GUI framework |
| [`egui_plot`](https://crates.io/crates/egui_plot) | Real-time traffic plotting |
| [`egui_extras`](https://crates.io/crates/egui_extras) | Additional egui widgets |
| [`chrono`](https://crates.io/crates/chrono) | Timestamp formatting |
| [`crossbeam-channel`](https://crates.io/crates/crossbeam-channel) | Multi-producer multi-consumer channels |

## Roadmap

- [ ] IPv6 support
- [ ] Packet capture file export (PCAP format)
- [ ] Packet search functionality
- [ ] Dark / Light theme toggle
- [ ] DNS query resolution display
- [ ] Network connection map visualization

## Contributing

Issues and pull requests are welcome at [GitHub](https://github.com/Jashiker/uSniffer).

## License

Licensed under [GNU General Public License v3.0](LICENSE).
