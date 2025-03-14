use futures::executor::block_on;
use ipnet::IpNet;
use log::{debug, error, info};
use shadowsocks::config::Mode;
use shadowsocks_service::config::Config;
use shadowsocks_service::local::context::ServiceContext;
use shadowsocks_service::local::loadbalancing::PingBalancerBuilder;
use shadowsocks_service::local::tun::{StaticDeviceNetHelper, TunBuilder};
use std::fmt::{format, Debug};
use std::{io, sync::Arc};
use std::os::fd::RawFd;
use clap::Command;
use futures::future::err;
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex};
use tokio::sync::mpsc::error::SendError;
use shadowsocks::relay::udprelay::DatagramReceiveExt;
use shadowsocks_rust::service::local;
use shadowsocks_rust::VERSION;
use crate::mobile_tun_device::TunError::{DeviceError, IoError};
/*

// Tunnel represents a session on a TUN device.
type Tunnel interface {
    // IsConnected is true if Disconnect has not been called.
    IsConnected() bool
    // Disconnect closes the underlying resources. Subsequent Write calls will fail.
    Disconnect()
    // Write writes input data to the TUN interface.
    Write(data []byte) (int, error)
}

Then the Swift code will create a tunnel, pass packets to it, and destroy the tunnel.


 */

#[derive(Debug)]
pub enum TunError {
    IoError(io::Error),
    SendError(SendError<Vec<u8>>),
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
pub struct
TunDeviceConfig {
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
    // pub device: Arc<Mutex<Option<TunBuilder>>>,
    pub config: String,
    pub fd: RawFd, //i32
    pub status: Arc<Mutex<VPNStatus>>,
    // sender: mpsc::UnboundedSender<Vec<u8>>,
    // receiver: Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
}

impl MobileTunDevice {
    pub async fn get_status_async(&self) -> VPNStatus {
        self.status.lock().await.clone()
    }
    async fn update_status(&self, status: VPNStatus) {
        let mut gg = self.status.lock().await;
        *gg = status;
    }

    pub async fn new(fd: i32, config: &str) -> Result<Self, TunError> {
        debug!("Creating TUN device with fd: {:?}", fd);

        // Create a TunBuilder using the existing shadowsocks implementation
        // let context = Arc::new(ServiceContext::new());
        // let mut balancer_builder = PingBalancerBuilder::new(context.clone(), Mode::TcpAndUdp);
        //
        // // Add servers from config
        // for server in &config.server {
        //     balancer_builder.add_server(server.clone());
        // }
        // // Build the balancer
        // let balancer = balancer_builder.build().await.map_err(|e| {
        //     error!("Failed to build balancer: {:?}", e);
        //     TunError::ConfigError("Failed to create balancer")
        // })?;
        //
        // // Create TunBuilder
        // let mut builder = TunBuilder::new(context.clone(), balancer);
        // builder.file_descriptor(tun_config.fd);
        // builder.address(tun_config.address);
        // if let Some(dest) = tun_config.destination {
        //     builder.destination(dest);
        // }
        // // Create the network helper with the configured addresses
        // let net_helper = StaticDeviceNetHelper::new(tun_config.address.addr(), tun_config.address.netmask());
        // builder.with_net_helper(net_helper);
        // builder.mode(Mode::TcpAndUdp);
        // let (s, r) = mpsc::unbounded_channel();
        let updated_config = Self::add_tun_device_fd_to_config(config, fd)
            .map_err(|err| {TunError::ConfigError("Failed to update config")})?;
        debug!("<< Using Config: {:?}", updated_config);
        Ok(MobileTunDevice {
            // device: Arc::new(Mutex::new(Some(builder))),
            config: updated_config,
            fd,
            status: Arc::new(Mutex::new(VPNStatus::new(VPNStatusCode::Started, None))),
            // sender: s,
            // receiver: Arc::new(Mutex::new(r)),
        })
    }

    // pub fn write(&self, buf: &[u8]) -> Result<usize, TunError> {
    //     match self.sender.send(Vec::from(buf)) {
    //         Ok(_) => Ok(buf.len()),
    //         Err(e) => Err(TunError::SendError(e))
    //     }
    // }

    fn add_tun_device_fd_to_config(config_json: &str, fd: i32) -> Result<String, io::Error> {
        // Parse the JSON input
        let mut config: Value = serde_json::from_str(config_json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid JSON: {}", e)))?;
        // Handle different config formats
        if let Some(locals) = config.get_mut("locals").and_then(Value::as_array_mut) {
            // Config format with "locals" array
            let mut found_tun = false;

            // Try to find a TUN local config
            for local in locals.iter_mut() {
                if let Some(protocol) = local.get("protocol") {
                    if protocol.as_str() == Some("tun") {
                        // Found a TUN config, update or add the fd
                        local["tun-device-fd"] = json!(fd);
                        found_tun = true;
                        break;
                    }
                }
            }
        }


        // Serialize back to string
        serde_json::to_string(&config)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to serialize JSON: {}", e)))
    }

    pub async fn start_tunnel(&self) -> Result<(), TunError> {
        info!("Starting TUN tunnel");
        self.update_status(VPNStatus::connecting()).await;

        let mut app = Command::new("shadowsocks").version(VERSION);
        app = local::define_command_line_options(app);

        let matches = app.get_matches();
        info!("<<<< one");
        let (config, runtime, main_fut) = local::create(&matches, Some(&self.config))
            .map_err(|msg| {
                error!("Local configuration failed: {}", msg);
                TunError::DeviceError("Failed to create SS_LOCAL: {:?}")
            })?;
        // let (_config, runtime, main_fut) = match local::create(&matches, Some(&self.config)) {
        //     Ok((cf, rt, fut)) => (cf, rt, fut),
        //     Err(err) => {
        //         let msg = format!("Failed to create Shadowsocks service: {}", err);
        //         // error!(msg);
        //         return Err(DeviceError(msg.clone().as_str()))
        //         // return Err(io::Error::new(
        //         //     io::ErrorKind::Other,
        //         //     format!("Service creation error: {}", err),
        //         // ));
        //     }
        // };
        debug!("<<<<<<<< {:?}", config);
        std::thread::spawn(move || {
            info!("Starting Shadowsocks service in background thread");

            // This is now safe because we're in a new OS thread
            match runtime.block_on(main_fut) {
                Ok(_) => {
                    info!("Shadowsocks service completed successfully");
                }
                Err(err) => {
                    error!("Shadowsocks service error: {}", err);
                }
            }
        });
        self.update_status(VPNStatus::connected()).await;

        Ok(())
        // let mut builder_lock = self.device.lock().await;
        //
        // // Take the builder out of the Option
        // let builder = builder_lock.take().ok_or_else(|| {
        //     let err = DeviceError("TUN device already started");
        //     block_on(async {
        //         self.update_status(VPNStatus::error("TUN device already started")).await;
        //     });
        //     err
        // })?;
        //
        // // Build the TUN device
        // let mut tun = builder.build().await.map_err(|e| {
        //     error!("Failed to build TUN device: {:?}", e);
        //     block_on(async {
        //         self.update_status(VPNStatus::error(&format!(
        //             "Failed to build TUN device: {:?}",
        //             e
        //         ))).await;
        //     });
        //    DeviceError("Failed to create TUN device")
        // })?;
        // // Release the lock before running
        // drop(builder_lock);
        //
        // // Create the handler and get receivers
        // // let mtu = 1500; // Standard MTU size
        // let mtu = 65536; // bigger size
        // self.update_status(VPNStatus::connected()).await;
        //
        // let result = tokio::select! {
        //     r = tun.run() => r,
        // };
        // match result {
        //     Ok(_) => {
        //         self.update_status(VPNStatus::disconnected()).await;
        //         Ok(())
        //     }
        //     Err(e) => {
        //         let status = VPNStatus::error(&format!("TUN device error: {:?}", e));
        //         self.update_status(status).await;
        //         Err(IoError(e))
        //     }
        // }
    }
}
