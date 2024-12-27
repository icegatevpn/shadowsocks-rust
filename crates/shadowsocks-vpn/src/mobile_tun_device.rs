use std::{io, sync::Arc};
use tokio::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use shadowsocks::config::Mode;
use shadowsocks_service::config::Config;
use tun2::{AsyncDevice, Configuration, Device};
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use log::{debug, error, info};
use crate::TunError;

pub struct MobileTunDevice {
    device: Arc<Mutex<AsyncDevice>>,
    config: Config,
    file_descriptor: i32,
}

impl MobileTunDevice {
    pub fn new(fd: i32, config: Config) -> Result<Self, TunError> {
        debug!("<< Creating TUN device with fd: {}", fd);

        // Create TUN configuration
        let mut tun_config = Configuration::default();
        tun_config.raw_fd(fd);
        tun_config.mtu(1500);

        // Create base Device
        let device = Device::new(&tun_config)
            .map_err(|e| TunError::DeviceError("Failed to create TUN device"))?;

        // Convert to AsyncDevice
        let async_device = AsyncDevice::new(device)

            .map_err(|e| {
                error!("FAILED!! {:?}", e);
                TunError::DeviceError("Failed to create async TUN device")
            })?;

        Ok(MobileTunDevice {
            device: Arc::new(Mutex::new(async_device)),
            config,
            file_descriptor: fd,
        })
    }

    pub async fn start_tunnel(&self) -> Result<(), TunError> {
        info!("Starting TUN tunnel");
        let device = self.device.clone();

        // Set up TCP/UDP relay handlers
        let tcp_relay = self.setup_tcp_relay().await?;
        let udp_relay = self.setup_udp_relay().await?;

        loop {
            let mut dev = device.lock().await;
            let mut buffer = vec![0u8; 1500]; // Standard MTU size

            match dev.read(&mut buffer).await {
                Ok(n) if n > 0 => {
                    // Try parsing as IPv4 first
                    if let Ok(ipv4) = Ipv4HeaderSlice::from_slice(&buffer[..n]) {
                        match ipv4.protocol() {
                            6 => { // TCP
                                if let Err(e) = tcp_relay.handle_packet(&buffer[..n]).await {
                                    error!("TCP handling error: {:?}", e);
                                }
                            },
                            17 => { // UDP
                                if let Err(e) = udp_relay.handle_packet(&buffer[..n]).await {
                                    error!("UDP handling error: {:?}", e);
                                }
                            },
                            _ => debug!("Ignoring non-TCP/UDP IPv4 packet"),
                        }
                    } else if let Ok(ipv6) = Ipv6HeaderSlice::from_slice(&buffer[..n]) {
                        match ipv6.next_header() {
                            6 => { // TCP
                                if let Err(e) = tcp_relay.handle_packet(&buffer[..n]).await {
                                    error!("TCP handling error: {:?}", e);
                                }
                            },
                            17 => { // UDP
                                if let Err(e) = udp_relay.handle_packet(&buffer[..n]).await {
                                    error!("UDP handling error: {:?}", e);
                                }
                            },
                            _ => debug!("Ignoring non-TCP/UDP IPv6 packet"),
                        }
                    } else {
                        debug!("Failed to parse IP packet");
                    }
                },
                Ok(_) => continue,
                Err(e) => {
                    error!("Error reading from TUN device: {}", e);
                    return Err(TunError::IoError(e));
                }
            }
        }
    }

    async fn setup_tcp_relay(&self) -> Result<TcpRelay, TunError> {
        Ok(TcpRelay::new(self.config.clone()))
    }

    async fn setup_udp_relay(&self) -> Result<UdpRelay, TunError> {
        Ok(UdpRelay::new(self.config.clone()))
    }

    pub async fn write_packet(&self, packet: &[u8]) -> Result<usize, TunError> {
        let mut dev = self.device.lock().await;
        dev.write(packet).await
            .map_err(TunError::IoError)
    }
}

/// TCP Relay handler using shadowsocks
struct TcpRelay {
    config: Config,
}

impl TcpRelay {
    fn new(config: Config) -> Self {
        TcpRelay { config }
    }

    async fn handle_packet(&self, packet: &[u8]) -> io::Result<()> {
        // Implement shadowsocks TCP relay logic
        Ok(())
    }
}

/// UDP Relay handler using shadowsocks
struct UdpRelay {
    config: Config,
}

impl UdpRelay {
    fn new(config: Config) -> Self {
        UdpRelay { config }
    }

    async fn handle_packet(&self, packet: &[u8]) -> io::Result<()> {
        // Implement shadowsocks UDP relay logic
        Ok(())
    }
}