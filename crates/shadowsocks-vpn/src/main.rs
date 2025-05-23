/*
   This is very much only for development and testing. the shadowsocks-vpn is a library, not a binary.
*/
#[cfg(target_os = "macos")]
mod macos_tun_device;

#[cfg(target_os = "windows")]
mod windows_tun_device;

#[cfg(target_os = "windows")]
use crate::windows_tun_device::WindowsTunDevice;
use log::{debug, error, info};
use std::ffi::CString;
use ipnet::IpNet;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use shadowsocks_vpn::{vpn_create, vpn_destroy, vpn_last_error, vpn_start, vpn_stop};
use std::io::ErrorKind;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;


#[cfg(any(target_os = "macos", target_os = "windows"))]
fn main() -> std::io::Result<()> {
    let pair = Arc::new((Mutex::new(true), Condvar::new()));
    let pair2 = pair.clone();
    // Set up signal handlers
    #[cfg(unix)]
    {
        use signal_hook::consts::{SIGINT, SIGTERM};
        use signal_hook::iterator::Signals;

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
        })
        .expect("Error setting Ctrl-C handler");
    }

    let config = format!(
        r#"{{
            "server": "45.86.229.176",
            "server_port": 443,
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
                    "tun_interface_address": "10.0.0.1/24"
                }},
                {{
                    "protocol":"dns",
                    "local_address": "127.0.0.1",
                    "local_port": 5450,
                    "local_dns_address": "local_dns_path",
                    "remote_dns_address": "dns.google",
                    "remote_dns_port": 53
	            }}
            ],
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
        return Err(std::io::Error::new(ErrorKind::InvalidData, "failed"));
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
