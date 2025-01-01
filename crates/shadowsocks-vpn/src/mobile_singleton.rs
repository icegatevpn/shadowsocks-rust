use std::sync::Arc;
use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use log::{debug, error};

use crate::mobile_tun_device::{MobileTunDevice, TunDeviceConfig, VPNStatus, VPNStatusCode};
use shadowsocks_service::config::{Config, ConfigType};

static INSTANCE: OnceCell<Arc<Mutex<Option<(Runtime, MobileTunDevice)>>>> = OnceCell::new();

pub struct MobileDeviceManager;

impl MobileDeviceManager {
    pub fn global() -> &'static Arc<Mutex<Option<(Runtime, MobileTunDevice)>>> {
        INSTANCE.get_or_init(|| Arc::new(Mutex::new(None)))
    }

    pub async fn initialize(config_str: &str, fd: i32) -> Result<(), String> {
        let mut guard = Self::global().lock().await;

        if guard.is_some() {
            return Err("VPN already initialized".to_string());
        }

        // Create runtime for async operations
        let runtime = Runtime::new()
            .map_err(|e| format!("Failed to create runtime: {}", e))?;

        // Load config
        let config = Config::load_from_str(config_str, ConfigType::Local)
            .map_err(|e| format!("Failed to load config: {}", e))?;

        // Create TUN device configuration
        let tun_config = TunDeviceConfig {
            fd,
            address: "10.1.10.2/24".parse().unwrap(),
            destination: Some("0.0.0.0/0".parse().unwrap()),
            mtu: Some(1500),
        };

        // Create TUN device
        let tun = runtime.block_on(async {
            MobileTunDevice::new(tun_config, config).await
                .map_err(|e| format!("Failed to create TUN device: {:?}", e))
        })?;

        *guard = Some((runtime, tun));
        Ok(())
    }

    pub async fn start() -> Result<i64, String> {
        let instance = Self::global();
        let mut guard = instance.lock().await;

        if let Some((runtime, tun)) = &mut *guard {
            let runtime_handle = runtime.handle().clone();

            // Take ownership of tun data needed for the task
            let tun = tun.clone();

            // Drop the guard before spawning the task
            drop(guard);

            // Spawn the tunnel task into the background
            runtime_handle.spawn(async move {
                debug!("Starting TUN device in background task");
                match tun.start_tunnel().await {
                    Ok(_) => {
                        debug!("TUN tunnel completed successfully");
                        VPNStatusCode::Connected.tou8() as i64
                    }
                    Err(e) => {
                        error!("TUN tunnel error: {:?}", e);
                        VPNStatusCode::Error.tou8() as i64
                    }
                }
            });

            Ok(VPNStatusCode::Connecting.tou8() as i64)
        } else {
            Err("VPN not initialized".to_string())
        }
    }

    pub async fn stop() -> Result<(), String> {
        let mut guard = Self::global().lock().await;
        *guard = None;
        Ok(())
    }

    pub async fn get_status() -> Result<VPNStatus, String> {
        let guard = Self::global().lock().await;

        if let Some((_, tun)) = guard.as_ref() {
            Ok(tun.get_status_async().await)
        } else {
            Ok(VPNStatus::new(VPNStatusCode::Disconnected, None))
        }
    }
}