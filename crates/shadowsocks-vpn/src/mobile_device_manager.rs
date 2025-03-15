use std::sync::Arc;
use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;
use tokio::sync::{Mutex, oneshot};
use log::{debug, error, info, warn};

use crate::mobile_tun_device::{MobileTunDevice, TunDeviceConfig, VPNStatus, VPNStatusCode};
use shadowsocks_service::config::{Config, ConfigType};

struct VpnState {
    runtime: Runtime,
    tun_device: MobileTunDevice,
    shutdown_tx: Option<oneshot::Sender<()>>,
}
static INSTANCE: OnceCell<Arc<Mutex<Option<VpnState>>>> = OnceCell::new();

pub struct MobileDeviceManager;

impl MobileDeviceManager {
    pub fn global() -> &'static Arc<Mutex<Option<VpnState>>> {
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

        // Create TUN device
        let tun = runtime.block_on(async {
            MobileTunDevice::new(fd, config_str).await
                .map_err(|e| format!("Failed to create TUN device: {:?}", e))
        })?;

        *guard = Some(VpnState {
            runtime,
            tun_device: tun,
            shutdown_tx: None,
        });

        Ok(())
    }

    pub async fn start() -> Result<i64, String> {
        let instance = Self::global();
        let mut guard = instance.lock().await;

        // if let Some((runtime, tun)) = &mut *guard {
        if let Some(state) = &mut *guard {
            let runtime_handle = state.runtime.handle().clone();

            // Take ownership of tun data needed for the task
            let tun = state.tun_device.clone();

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            state.shutdown_tx = Some(shutdown_tx);

            // Drop the guard before spawning the task
            drop(guard);

            // Spawn the tunnel task into the background
            let task = runtime_handle.spawn(async move {
                debug!("Starting TUN device in background task");

                // Use select to make the task cancellable
                tokio::select! {
                    result = tun.start_tunnel() => {
                        match result {
                            Ok(_) => {
                                info!("TUN tunnel completed successfully");
                                VPNStatusCode::Connected.tou8() as i64
                            }
                            Err(e) => {
                                error!("TUN tunnel error: {:?}", e);
                                VPNStatusCode::Error.tou8() as i64
                            }
                        }
                    }
                    _ = shutdown_rx => {
                        info!("TUN tunnel shutdown requested");
                        VPNStatusCode::Disconnected.tou8() as i64
                    }
                }
            });

            Ok(VPNStatusCode::Connecting.tou8() as i64)
        } else {
            Err("VPN not initialized".to_string())
        }
    }

    pub async fn stop() -> Result<(), String> {
        warn!("Stopping VPN service");
        let mut guard = Self::global().lock().await;

        if let Some(state) = guard.as_mut() {
            _ = state.tun_device.cancel().await;

            // Signal the running task to stop
            if let Some(shutdown_tx) = state.shutdown_tx.take() {
                // It's okay if the receiver is already dropped
                _ = shutdown_tx.send(());
                info!("Shutdown signal sent to VPN task");
            }

            // Allow a little time for cleanup in the background thread
            let runtime = &state.runtime;
            runtime.spawn(async {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                debug!("Cleanup delay completed");
            });

            // Remove the state after sending the shutdown signal
            *guard = None;

            Ok(())
        } else {
            warn!("Attempted to stop VPN service that wasn't running");
            Ok(())
        }
    }

    pub async fn get_status() -> Result<VPNStatus, String> {
        let guard = Self::global().lock().await;

        if let Some(state) = guard.as_ref() {
            Ok(state.tun_device.get_status_async().await)
        } else {
            Ok(VPNStatus::new(VPNStatusCode::Disconnected, None))
        }
    }
}