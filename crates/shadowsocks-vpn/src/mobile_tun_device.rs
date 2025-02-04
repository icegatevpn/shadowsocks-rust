use log::{debug, error, info};
use shadowsocks::config::Mode;
use shadowsocks_service::config::Config;
use shadowsocks_service::local::context::ServiceContext;
use shadowsocks_service::local::loadbalancing::{PingBalancerBuilder};
use shadowsocks_service::local::tun::{StaticDeviceNetHelper, TunBuilder};
use std::{io, sync::Arc};
use std::fmt::Debug;
use tokio::sync::Mutex;
use ipnet::IpNet;
use futures::executor::block_on;

#[derive(Debug)]
pub enum TunError {
    IoError(io::Error),
    ConfigError(&'static str),
    DeviceError(&'static str),
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum VPNStatusCode {
    Started = 0,
    Connecting = 1,
    Connected = 2,
    Disconnected = 3,
    Error = 4,
}
impl VPNStatusCode {
    pub fn tou8(&self) -> u8 {
        *self as u8
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct VPNStatus {
    pub code: VPNStatusCode,
    pub message: Option<String>,
}
impl VPNStatus {
    pub fn new(code: VPNStatusCode, message: Option<String>) -> Self {
        VPNStatus { code, message }
    }

    pub fn connecting() -> Self {
        VPNStatus::new(VPNStatusCode::Connecting, None)
    }

    pub fn connected() -> Self {
        VPNStatus::new(VPNStatusCode::Connected, None)
    }

    pub fn disconnected() -> Self {
        VPNStatus::new(VPNStatusCode::Disconnected, None)
    }

    pub fn error(msg: &str) -> Self {
        VPNStatus::new(VPNStatusCode::Error, Some(msg.to_string()))
    }
}
#[derive(Clone)]
pub struct TunDeviceConfig {
    pub fd: i32,
    pub address: IpNet,
    pub destination: Option<IpNet>,
    pub mtu: Option<i32>,
}
impl Debug for TunDeviceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunDeviceConfig")
            .field("address", &self.address)
            .field("destination", &self.destination)
            .field("fd", &self.fd)
            .field("mtu", &self.mtu)
            .finish()

    }
}
#[derive(Clone)]
pub struct MobileTunDevice {
    // Store the builder until we're ready to build
    device: Arc<Mutex<Option<TunBuilder>>>,
    pub status: Arc<Mutex<VPNStatus>>,
}

impl MobileTunDevice {
    pub async fn get_status_async(&self) -> VPNStatus {
        self.status.lock().await.clone()
    }
    async fn update_status(&self, status: VPNStatus) {
        let mut gg = self.status.lock().await;
        *gg = status;
    }

    pub async fn new(tun_config: TunDeviceConfig, config: Config) -> Result<Self, TunError> {
        debug!("Creating TUN device with config: {:?}", tun_config);

        // Create a TunBuilder using the existing shadowsocks implementation
        let context = Arc::new(ServiceContext::new());
        let mut balancer_builder = PingBalancerBuilder::new(
            context.clone(),
            Mode::TcpAndUdp,
        );

        // Add servers from config
        for server in &config.server {
            balancer_builder.add_server(server.clone());
        }
        // Build the balancer
        let balancer = balancer_builder.build().await.map_err(|e| {
            error!("Failed to build balancer: {:?}", e);
            TunError::ConfigError("Failed to create balancer")
        })?;

        // Create TunBuilder
        let mut builder = TunBuilder::new(context.clone(), balancer);
        builder.file_descriptor(tun_config.fd);
        builder.address(tun_config.address);
        if let Some(dest) = tun_config.destination {
            builder.destination(dest);
        }
        // Create the network helper with the configured addresses
        let net_helper = StaticDeviceNetHelper::new(
            tun_config.address.addr(),
            tun_config.address.netmask()
        );
        builder.with_net_helper(net_helper);

        builder.mode(Mode::TcpAndUdp);
        builder.name("shadowsocks-rust-tun-device");

        Ok(MobileTunDevice {
            device: Arc::new(Mutex::new(Some(builder))),
            status: Arc::new(Mutex::new(VPNStatus::new(VPNStatusCode::Started, None))),
        })
    }

    pub async fn start_tunnel(&self) -> Result<(), TunError> {
        info!("Starting TUN tunnel");
        self.update_status(VPNStatus::connecting()).await;

        let mut device_lock = self.device.lock().await;

        // Take the builder out of the Option
        if let Some(builder) = device_lock.take() {
            let tun = builder.build().await.map_err( |e|  {
                error!("Failed to build TUN device: {:?}", e);
                block_on(async move {
                    self.update_status(VPNStatus::error(&format!("Failed to build TUN device: {:?}", e))).await;
                });
                TunError::DeviceError("Failed to create TUN device")
            }).expect("Failed to build TUN device");

            // Release the lock before running
            drop(device_lock);

            self.update_status(VPNStatus::connected()).await;

            // Run the TUN device
            match tun.run().await {
                Ok(_) => {
                    let status = VPNStatus::disconnected();
                    self.update_status(status.clone()).await;
                    Ok(())
                }
                Err(e) => {
                    let status = VPNStatus::error(&format!("Failed to run TUN device: {:?}", e));
                    self.update_status(status.clone()).await;
                    Err(TunError::IoError(e))

                }
            }
        } else {
            let status = VPNStatus::error("TUN device already started");
            self.update_status(status.clone()).await;
            Err(TunError::DeviceError("TUN device already started"))
        }
    }
}
