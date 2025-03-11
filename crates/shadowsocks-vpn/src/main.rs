/*
    This is very much only for development and testing. the shadowsocks-vpn is a library, not a binary.
 */
#[cfg(target_os = "macos")]
mod macos_tun_device;

#[cfg(target_os = "windows")]
mod windows_tun_device;

use std::ffi::CString;
use log::{debug, error, info};
#[cfg(target_os = "windows")]
use crate::windows_tun_device::WindowsTunDevice;

// #[cfg(target_os = "windows")]
// #[async_trait::async_trait]
// impl TunDevice for WindowsTunDevice {
//     async fn start(&mut self) -> std::io::Result<()> {
//         WindowsTunDevice::start(self).await
//     }
//
//     async fn stop(&self) -> std::io::Result<()> {
//         WindowsTunDevice::stop(self).await
//     }
//
//     async fn is_running(&self) -> bool {
//         WindowsTunDevice::is_running(self).await
//     }
// }
use std::{thread};
use std::io::ErrorKind;
use std::sync::{Arc, Condvar, Mutex};
use ipnet::IpNet;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use shadowsocks_vpn::{vpn_create, vpn_destroy, vpn_last_error, vpn_start, vpn_stop};

//
// #[tokio::main]
// async fn main() -> io::Result<()> {
//     // Initialize logging
//     env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
//
//     // Example shadowsocks configuration
//     let config = Config::load_from_str(
//         r#"{
//             "server": "46.249.38.167",
//             "server_port": 8488,
//             "password": "yJxlMnbXB0fpbQ+YfBwmV4GVr1ndRbsEJXdrJFQNeRE=:aj0Wg39ZA/h6dUuZr60T3kMHRpQQDIivPeSOYi397C4=",
//             "method": "2022-blake3-aes-256-gcm",
//             "mode": "tcp_and_udp",
//             "locals": [
//                 {
//                     "protocol": "tun",
//                     "local_address": "10.10.0.2",
//                     "local_port": 1086,
//                     "mode": "tcp_and_udp"
//                 }
//             ],
//             "dns": "8.8.8.8,8.8.4.4",
//             "no_delay": true,
//             "keep_alive": 15,
//             "timeout": 300
//         }"#,
//         ConfigType::Local
//     ).expect("Failed to parse config");
//
//     // TUN device configuration
//     let tun_config = IosMacTunConfig {
//         address: "10.10.0.2/24".parse::<IpNet>().expect("Invalid address"),
//         destination: Some("0.0.0.0/0".parse::<IpNet>().expect("Invalid destination")),
//         mtu: Some(1500),
//     };
//
//     // Create the TUN device
//     let tun_device = IosMacTunDevice::new(tun_config, config)
//         .await
//         .expect("Failed to create TUN device");
//
//     // Get adapter for writing test data if needed
//     let adapter = tun_device.get_adapter();
//
//     // Spawn a task to read outbound packets
//     let tun_clone = tun_device.clone();
//     tokio::spawn(async move {
//         loop {
//             match tun_clone.read_outbound().await {
//                 Ok(data) => {
//                     debug!("Received outbound packet: {} bytes", data.len());
//                 },
//                 Err(e) => {
//                     error!("Error reading outbound packet: {}", e);
//                     break;
//                 }
//             }
//         }
//     });
//
//     // Start the tunnel
//     info!("Starting TUN device...");
//
//     // Handle shutdown gracefully
//     let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
//
//     // Spawn the tunnel in a separate task
//     let tun_handle = tokio::spawn(async move {
//         if let Err(e) = tun_device.start_tunnel().await {
//             error!("Tunnel error: {}", e);
//         }
//     });
//
//     // Wait for Ctrl-C
//     tokio::select! {
//         _ = signal::ctrl_c() => {
//             info!("Received Ctrl+C, shutting down...");
//             let _ = shutdown_tx.send(());
//         }
//         _ = tun_handle => {
//             error!("Tunnel stopped unexpectedly");
//         }
//     }
//
//     info!("Shutdown complete");
//     Ok(())
// }

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn main() -> std::io::Result<()> {

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

    /*
    MACOS:
sslocal --protocol tun -s "[::1]:8388" -m "aes-256-gcm" -k "hello-kitty" --outbound-bind-interface lo0 --tun-interface-address 10.255.0.1/24

     */

    let config = format!(
        r#"{{
            "server": "46.249.35.130",
            "server_port": 8765,
            "password": "yJxlMnbXB0fpbQ+YfBwmV4GVr1ndRbsEJXdrJFQNeRE=:aj0Wg39ZA/h6dUuZr60T3kMHRpQQDIivPeSOYi397C4=",
            "method": "2022-blake3-aes-256-gcm",
            "mode": "tcp_and_udp",
            "locals": [
                {{
                    "protocol": "tun",
                    "local_address": "127.0.0.1",
                    "local_port": 1086,
                    "mode": "tcp_and_udp",
                    "tun_interface_name": "utun666",
                    "tun_interface_address": "10.13.2.1/24"
                }},
                {{
                  "local_address": "127.0.0.1",
                  "local_port": 5450,
                  "local_dns_address": "114.114.114.114",
                  "local_dns_port": 53,
                  "remote_dns_address": "8.8.8.8",
                  "remote_dns_port": 53,
                  "protocol": "dns"
                }}
            ],
            "dns": "8.8.8.8,8.8.4.4",
            "no_delay": true,
            "keep_alive": 15,
            "timeout": 300,
            "log": {{
            	"level": 1,
             }},
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
