mod macos_tun_device;
#[cfg(target_os = "windows")]
mod windows_tun_device;

use std::ffi::CString;
use log::{debug, error, info};
use shadowsocks_service::config::{Config, ConfigType};
#[cfg(target_os = "windows")]
use crate::windows_tun_device::WindowsTunDevice;
use tokio::signal;


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

use std::process::Command;
use std::{thread};
use std::io::ErrorKind;
use std::sync::{Arc, Condvar, Mutex};
#[cfg(not(target_os = "android"))]
use shadowsocks_vpn::{vpn_create, vpn_destroy, vpn_last_error, vpn_start, vpn_stop};

#[cfg(not(target_os = "android"))]
fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let pair = Arc::new((Mutex::new(true), Condvar::new()));
    let pair2 = pair.clone();
    // Set up signal handlers
    #[cfg(unix)]
    {
        use signal_hook::iterator::Signals;
        use signal_hook::consts::{SIGINT, SIGTERM};

        let mut signals = Signals::new(&[SIGINT, SIGTERM]).unwrap();
        thread::spawn(move || {
            for sig in signals.forever() {
                info!("Received signal {}", sig);
                let (lock, cvar) = &*pair2;
                let mut running = lock.lock().unwrap();
                *running = false;
                cvar.notify_all();
                break;
            }
        });
    }

    #[cfg(windows)]
    {
        let pair3 = pair2.clone();
        ctrlc::set_handler(move || {
            info!("Received Ctrl+C");
            let (lock, cvar) = &*pair3;
            let mut running = lock.lock().unwrap();
            *running = false;
            cvar.notify_all();
        }).expect("Error setting Ctrl-C handler");
    }

    let config = format!(
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
    );
    let c_string = CString::new(config).expect("CString::new failed");
    let vpn = vpn_create(c_string.as_ptr());

    if !vpn_start(vpn) {
        vpn_destroy(vpn);
        let error = vpn_last_error();
        error!("Error: {:?}\n", error);
        return Err(std::io::Error::new(ErrorKind::InvalidData,"failed"))
    }

    debug!("VPN is Running...");
    // Wait for shutdown signal
    let (lock, cvar) = &*pair;
    let mut running = lock.lock().unwrap();
    while *running {
        running = cvar.wait(running).unwrap();
    }

    info!("VPN stopped successfully");

    vpn_stop(vpn);
    vpn_destroy(vpn);
    Ok(())
}
