mod macos_tun_device;
#[cfg(target_os = "windows")]
mod windows_tun_device;

use log::{debug, error, info};
use shadowsocks_service::config::{Config, ConfigType};
use crate::macos_tun_device::MacOSTunDevice;
use tokio::signal;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    debug!("starting server");
    //"mode": "tcp_and_udp",
    let config = Config::load_from_str(
        &format!(
            r#"{{
            "server": "165.232.76.105",
            "server_port": 8388,
            "password": "xXsEZIlaGPEtkuDZ4ZKM2lcFqtY74WcuUeLo+1384Gc=:0X7im12oWeEc1kpA6JKS9ATf4SNZl/cObLgicta1T+o=",
            "method": "2022-blake3-aes-256-gcm",
            "protocol": "tun",
            "mode": "tcp_only",
            "locals": [
                {{
                    "protocol": "tun",
                    "local_address": "10.0.0.1",
                    "local_port": 8080,
                    "mode": "tcp_and_udp"
                }}
            ],
            "dns": "8.8.8.8,8.8.4.4",
            "no_delay": true,
            "keep_alive": 15,
            "timeout": 300
        }}"#
        ), ConfigType::Local).expect("failed to build config");
    // Load your shadowsocks config
    // let config = Config::load_from_file("config.json", ConfigType::Local)
    //     .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // Create TUN device
    let mut tun = MacOSTunDevice::new(config)?;

    // Start the VPN
    info!("Starting VPN service...");
    if let Err(err) = tun.start().await {
        error!("Failed to start VPN: {}", err);
        return Err(err);
    }
    info!("VPN service started successfully. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Shutdown signal received, stopping VPN...");
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
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
