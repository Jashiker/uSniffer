use pnet::datalink::{self, NetworkInterface, Config};
use pnet::ipnetwork;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

/// Network interface management
pub struct InterfaceManager;

impl InterfaceManager {
    /// Get all available network interfaces
    pub fn get_interfaces() -> Vec<NetworkInterface> {
        let mut ifaces = Vec::new();
        let interfaces = datalink::interfaces();

        for interface in interfaces {
            let ip: Vec<Ipv4Addr> = interface
                .ips
                .iter()
                .filter_map(|ip| match ip {
                    ipnetwork::IpNetwork::V4(ipv4) => Some(ipv4.ip()),
                    _ => None,
                })
                .collect();

            if !ip.is_empty()
                && !interface.is_loopback()
                && interface.is_running()
                && interface.is_up()
            {
                ifaces.push(interface);
            }
        }
        ifaces
    }

    /// Find interface by name
    pub fn find_interface_by_name(name: &str) -> Option<NetworkInterface> {
        Self::get_interfaces()
            .into_iter()
            .find(|iface| iface.name == name)
    }

    /// Get interface by index
    pub fn get_interface_by_index(index: usize) -> Option<NetworkInterface> {
        Self::get_interfaces().into_iter().nth(index)
    }
}

/// Network sniffer for capturing packets with proper resource management
pub struct NetworkSniffer {
    interface: NetworkInterface,
    promiscuous_mode: bool,
    thread_handle: Option<JoinHandle<()>>,
    stop_flag: Arc<AtomicBool>,
}

impl NetworkSniffer {
    pub fn new(interface: NetworkInterface, promiscuous_mode: bool) -> Self {
        Self {
            interface,
            promiscuous_mode,
            thread_handle: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start sniffing packets with proper thread management
    pub fn start_sniffing<F>(&mut self, packet_handler: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: Fn(&[u8]) -> bool + Send + 'static,
    {
        // Stop any existing sniffing thread first
        self.stop_sniffing();

        // Reset the stop flag for the new thread
        self.stop_flag.store(false, Ordering::Relaxed);

        let interface = self.interface.clone();
        let promiscuous_mode = self.promiscuous_mode;
        let stop_flag = Arc::clone(&self.stop_flag);

        let thread_handle = thread::spawn(move || {
            let mut config = Config::default();
            config.promiscuous = promiscuous_mode;

            let (_tx, mut rx) = match datalink::channel(&interface, config) {
                Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => {
                    eprintln!("Unhandled channel type");
                    return;
                }
                Err(e) => {
                    eprintln!("Failed to create datalink channel: {}", e);
                    return;
                }
            };

            println!("Started sniffing on interface: {}", interface.name);

            loop {
                // Check if we should stop before each packet read
                if stop_flag.load(Ordering::Relaxed) {
                    println!("Stopping packet capture on interface: {}", interface.name);
                    break;
                }

                match rx.next() {
                    Ok(packet) => {
                        if !packet_handler(&packet) {
                            println!("Packet handler requested stop");
                            break;
                        }
                    }
                    Err(e) => {
                        // Only print error if we're not stopping
                        if !stop_flag.load(Ordering::Relaxed) {
                            eprintln!("An error occurred while reading packet: {}", e);
                        }
                        // Brief pause before retrying
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
            }

            println!("Packet capture thread ended for interface: {}", interface.name);
        });

        self.thread_handle = Some(thread_handle);
        Ok(())
    }

    /// Stop sniffing and clean up resources
    pub fn stop_sniffing(&mut self) {
        if let Some(handle) = self.thread_handle.take() {
            // Signal the thread to stop
            self.stop_flag.store(true, Ordering::Relaxed);

            // Wait for the thread to finish (with timeout)
            match handle.join() {
                Ok(_) => println!("Sniffing thread stopped successfully"),
                Err(e) => eprintln!("Error joining sniffing thread: {:?}", e),
            }
        }
    }

    /// Check if currently sniffing
    pub fn is_sniffing(&self) -> bool {
        self.thread_handle.is_some() && !self.stop_flag.load(Ordering::Relaxed)
    }
}

impl Drop for NetworkSniffer {
    fn drop(&mut self) {
        self.stop_sniffing();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_interfaces() {
        let interfaces = InterfaceManager::get_interfaces();
        // We can't predict how many interfaces will be available,
        // but we can test that the function doesn't panic
        assert!(interfaces.len() >= 0);
    }
}
