use clap::Command;
use ipnet::IpNet;
use serde_json::{json, Value};
use shadowsocks::relay::udprelay::DatagramReceiveExt;
use shadowsocks_rust::service::local;
use shadowsocks_rust::VERSION;
use shadowsocks_service::{my_debug, my_error, my_info, my_warn};
use std::fmt::{Debug};
use std::{io, sync::Arc};
use tokio::sync::{mpsc, Mutex};

#[derive(Debug)]
pub enum TunError {
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
    pub config: String,
    pub status: Arc<Mutex<VPNStatus>>,
    shutdown_signal: Arc<Mutex<Option<mpsc::Sender<()>>>>,
}

impl MobileTunDevice {
    pub async fn get_status_async(&self) -> VPNStatus {
        self.status.lock().await.clone()
    }

    async fn update_status(&self, status: VPNStatus) {
        let mut gg = self.status.lock().await;
        *gg = status;
    }

    fn add_tun_device_fd_to_config(config_json: &str, fd: i32) -> Result<String, io::Error> {
        // Parse the JSON input
        let mut config: Value = serde_json::from_str(config_json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Invalid JSON: {}", e)))?;
        // Handle different config formats
        if cfg!(target_os = "ios") || cfg!(target_os = "tvos") {
            // I don't know how to add this to the json in swift,
            // this just prevents local from initializing logging again, which crashes the service
            config["rust_log_lvl"] = json!("none");
        }
        if let Some(locals) = config.get_mut("locals").and_then(Value::as_array_mut) {
            // Config format with "locals" array
            let mut found_tun = false;

            // Try to find a TUN local config
            for local in locals.iter_mut() {
                if let Some(protocol) = local.get("protocol") {
                    if protocol.as_str() == Some("tun") {
                        // Found a TUN config, update or add the fd
                        local["tun_device_fd"] = json!(fd);
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

    pub async fn new(fd: i32, config: &str) -> Result<Self, TunError> {
        my_debug!("Creating TUN device with fd: {:?}", fd);
        let updated_config = Self::add_tun_device_fd_to_config(config, fd).map_err(|err| {
            my_error!("Failed to update config: {}", err);
            TunError::ConfigError("Failed to update config")
        })?;
        Ok(MobileTunDevice {
            config: updated_config,
            status: Arc::new(Mutex::new(VPNStatus::new(VPNStatusCode::Started, None))),
            shutdown_signal: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn start_tunnel(&self) -> Result<(), TunError> {
        self.update_status(VPNStatus::connecting()).await;
        // First, create the shutdown channel
        let (tx, mut rx) = mpsc::channel::<()>(1);
        // Store the sender for cancellation
        {
            let mut signal = self.shutdown_signal.lock().await;
            *signal = Some(tx);
        }
        let mut app = Command::new("shadowsocks").version(VERSION);
        app = local::define_command_line_options(app);

        let matches = app
            .try_get_matches_from::<_, &str>(vec!["shadowsocks"])
            .expect("no matches :(");
        let create_result = local::create(&matches, Some(&self.config));
        match create_result {
            Ok((config, runtime, main_fut)) => {
                let status_clone = self.status.clone();
                std::thread::spawn(move || {
                    my_info!("Starting Shadowsocks service in background thread");

                    // Create a shutdown-aware future
                    let combined_fut = async move {
                        tokio::select! {
                            result = main_fut => {
                                match result {
                                    Ok(_) => {
                                        my_info!("Shadowsocks service completed successfully");
                                        VPNStatus::disconnected()
                                    }
                                    Err(err) => {
                                        let msg = format!("Shadowsocks service error: {}", err);
                                        my_error!("{}", msg);
                                        VPNStatus::error(&msg)
                                    }
                                }
                            }
                            _ = rx.recv() => {
                                my_info!("Shutdown signal received, stopping Shadowsocks service");
                                VPNStatus::disconnected()
                            }
                        }
                    };

                    // Run the combined future in the runtime
                    let final_status = runtime.block_on(combined_fut);
                    // Update status after completion
                    runtime.block_on(async {
                        let mut status = status_clone.lock().await;
                        *status = final_status;
                    });

                    // Runtime will be dropped here, cleaning up any remaining tasks
                });

                // Wait a short time to see if the service starts successfully
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                self.update_status(VPNStatus::connected()).await;

                // No need to join the thread here - it should run independently
                Ok(())
            }
            Err(err) => {
                let err_msg = format!("Failed to create Shadowsocks service: {}", err);
                my_error!("{}", err_msg);
                self.update_status(VPNStatus::error(&err_msg)).await;
                Err(TunError::DeviceError("Failed to create Shadowsocks service"))
            }
        }
    }

    pub async fn cancel(&self) -> Result<(), TunError> {
        my_info!("Cancelling TUN tunnel");

        // Get the shutdown sender if available
        let mut signal = self.shutdown_signal.lock().await;

        if let Some(tx) = signal.take() {
            // Send the shutdown signal
            if let Err(err) = tx.send(()).await {
                my_warn!("Failed to send shutdown signal: {}", err);
                // Continue anyway - the receiver might be dropped if the task completed naturally
            }

            // Update status to disconnected
            self.update_status(VPNStatus::disconnected()).await;
            Ok(())
        } else {
            my_warn!("No active tunnel to cancel");
            Ok(())
        }
    }
}
