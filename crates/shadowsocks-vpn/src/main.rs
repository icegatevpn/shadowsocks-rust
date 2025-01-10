mod macos_tun_device;
#[cfg(target_os = "windows")]
mod windows_tun_device;

use log::{debug, error, info};
use shadowsocks_service::config::{Config, ConfigType};
#[cfg(target_os = "macos")]
use crate::macos_tun_device::MacOSTunDevice;
#[cfg(target_os = "windows")]
use crate::windows_tun_device::WindowsTunDevice;
use tokio::signal;

// Define a trait for common TUN device operations
#[async_trait::async_trait]
trait TunDevice {
    async fn start(&mut self) -> std::io::Result<()>;
    async fn stop(&self) -> std::io::Result<()>;
    async fn is_running(&self) -> bool;
}

#[cfg(target_os = "macos")]
#[async_trait::async_trait]
impl TunDevice for MacOSTunDevice {
    async fn start(&mut self) -> std::io::Result<()> {
        MacOSTunDevice::start(self).await
    }

    async fn stop(&self) -> std::io::Result<()> {
        MacOSTunDevice::stop(self).await
    }

    async fn is_running(&self) -> bool {
        MacOSTunDevice::is_running(self).await
    }
}

#[cfg(target_os = "windows")]
#[async_trait::async_trait]
impl TunDevice for WindowsTunDevice {
    async fn start(&mut self) -> std::io::Result<()> {
        WindowsTunDevice::start(self).await
    }

    async fn stop(&self) -> std::io::Result<()> {
        WindowsTunDevice::stop(self).await
    }

    async fn is_running(&self) -> bool {
        WindowsTunDevice::is_running(self).await
    }
}

fn create_tun_device(config: Config) -> std::io::Result<Box<dyn TunDevice>> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(MacOSTunDevice::new(config)?))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(WindowsTunDevice::new(config)?))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Platform not supported"
        ))
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    debug!("starting server");

    // Set up panic hook for cleanup
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        error!("Panic occurred: {}", panic_info);
        default_panic(panic_info);
    }));

    // Set up exit hook
    let _cleanup_guard = scopeguard::guard((), |_| {
        debug!("Running cleanup on program exit");
    });

    let config = Config::load_from_str(
        &format!(
            r#"{{
            "server": "165.232.76.105",
            "server_port": 8388,
            "password": "xXsEZIlaGPEtkuDZ4ZKM2lcFqtY74WcuUeLo+1384Gc=:0X7im12oWeEc1kpA6JKS9ATf4SNZl/cObLgicta1T+o=",
            "method": "2022-blake3-aes-256-gcm",
            "protocol": "tun",
            "mode": "tcp_and_udp",
            "locals": [
                {{
                    "protocol": "tun",
                    "local_address": "10.10.0.2",
                    "local_port": 8080,
                    "mode": "tcp_and_udp",
                    "tun_interface_address": "10.10.0.2/24",
                    "tun_interface_name": "icetun",
                }}
            ],
            "dns": "8.8.8.8,8.8.4.4",
            "no_delay": true,
            "keep_alive": 15,
            "timeout": 300
        }}"#
        ), ConfigType::Local).expect("failed to build config");

    // Create platform-specific TUN device
    let mut tun = create_tun_device(config)?;

    // Start the VPN
    info!("Starting VPN service...");
    if let Err(err) = tun.start().await {
        error!("Failed to start VPN: {}", err);
        return Err(err);
    }
    info!("VPN service started successfully. Press Ctrl+C to stop.");

    // Wait for shutdown signals
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap()
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    let ctrl_c = async {
        signal::ctrl_c().await.unwrap();
    };

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal, stopping VPN...");
        }
        _ = terminate => {
            info!("Received terminate signal, stopping VPN...");
        }
    }

    // Stop the VPN
    info!("Stopping VPN service...");
    if let Err(err) = tun.stop().await {
        error!("Error while stopping VPN: {}", err);
        return Err(err);
    }
    info!("VPN service stopped successfully");

    Ok(())
}