mod mobile_tun_device;

use std::{io, ptr};
use std::sync::Arc;
use tokio::runtime::Runtime;
use shadowsocks_service::{config::{Config, ConfigType}, run_local};
use tokio::sync::oneshot;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use log::{debug, error, info, warn};
use crate::VPNError::ConfigError;


pub struct ShadowsocksVPN {
    runtime: Runtime,
    config: Config,
    running: Arc<AtomicBool>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

#[derive(Debug, thiserror::Error)]
pub enum VPNError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Runtime error: {0}")]
    RuntimeError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String)
}

#[derive(Debug)]
pub enum TunError {
    IoError(io::Error),
    ConfigError(&'static str),
    DeviceError(&'static str),
}

impl From<io::Error> for TunError {
    fn from(error: io::Error) -> Self {
        TunError::IoError(error)
    }
}

impl ShadowsocksVPN {
    pub fn new(config: Config) -> Result<Self, VPNError> {
        match config.check_integrity() {
            Ok(_) => {
                let runtime = Runtime::new()
                    .map_err(|e| VPNError::RuntimeError(e.to_string()))?;

                Ok(Self {
                    runtime,
                    config,
                    running: Arc::new(AtomicBool::new(false)),
                    shutdown_tx: None,
                })
            },
            Err(err) => {
                error!("{}", ConfigError(format!("{:?}", err)));
                Err(VPNError::ConfigError(format!("{:?}", err)))
            }
        }
    }

    pub fn start(&mut self) -> Result<(), VPNError> {
        debug!("<< starting VPN");
        if self.running.load(Ordering::Acquire) {
            warn!("VPN already running");
            return Ok(());
        }
        let config = self.config.clone();
        let running = self.running.clone();
        // Create a shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        debug!("starting server");
        // Spawn the server in the runtime
        self.runtime.spawn(async move {
            debug!("in runtime");
            running.store(true, Ordering::Release);
            info!("VPN runtime started: ${:?}", config);

            let server = run_local(config);
            let shutdown_rx = Box::pin(shutdown_rx);
            debug!("Local server started");

            tokio::select! {
                result = server => {
                    match result {
                        Ok(_) => debug!("Server completed normally"),
                        Err(e) => error!("Server error: {}", e),
                    }
                }
                _ = shutdown_rx => {
                    debug!("Received shutdown signal");
                }
            }

            running.store(false, Ordering::Release);
        });

        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), VPNError> {
        if !self.running.load(Ordering::Acquire) {
            debug!("VPN not running");
            return Ok(());
        }

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Wait for the server to stop
        let running = self.running.clone();
        self.runtime.block_on(async move {
            while running.load(Ordering::Acquire) {
                // todo, do wait step magic
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        debug!("VPN stopped");
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    // Add methods for managing the VPN connection
    pub fn update_config(&mut self, config: Config) -> Result<(), VPNError> {
        if self.is_running() {
            self.stop()?;
        }
        self.config = config;
        if !self.is_running() {//self.running.load(Ordering::Acquire) {
            self.start()?;
        }
        Ok(())
    }
}

// Implement common VPN functionality
pub trait VPNService {
    fn connect(&mut self) -> Result<(), VPNError>;
    fn disconnect(&mut self) -> Result<(), VPNError>;
    fn is_connected(&self) -> bool;
    fn get_status(&self) -> VPNStatus;
}

#[derive(Debug, Clone)]
pub enum VPNStatus {
    Connected,
    Connecting,
    Disconnected,
    Error(String)
}

impl VPNService for ShadowsocksVPN {
    fn connect(&mut self) -> Result<(), VPNError> {
        self.start()
    }

    fn disconnect(&mut self) -> Result<(), VPNError> {
        self.stop()
    }

    fn is_connected(&self) -> bool {
        self.is_running()
    }

    fn get_status(&self) -> VPNStatus {
        if self.is_running() {
            VPNStatus::Connected
        } else {
            VPNStatus::Disconnected
        }
    }
}


#[cfg(any(target_os = "android", target_os = "ios"))]
mod mobile {
    use super::*;
    use std::sync::Arc;
    use jni::sys::JavaVM;
    use tokio::sync::Mutex;
    use crate::mobile_tun_device::MobileTunDevice;

    /// Extended ShadowsocksVPN struct for mobile platforms
    // pub struct MobileVPN {
    //     inner: ShadowsocksVPN,
    //     tun_device: Option<Arc<MobileTunDevice>>,
    // }
    //
    // impl MobileVPN {
    //     pub async fn new(config: Config) -> Result<Self, VPNError> {
    //         Ok(MobileVPN {
    //             inner: ShadowsocksVPN::new(config)?,
    //             tun_device: None,
    //         })
    //     }
    //
    //     pub fn start(&mut self) -> Result<(), VPNError> {
    //         // Start the shadowsocks VPN service
    //         self.inner.start()?;
    //
    //         // If TUN device is configured, start the tunnel
    //         if let Some(tun) = &self.tun_device {
    //             let tun_clone = tun.clone();
    //             tokio::spawn(async move {
    //                 if let Err(e) = tun_clone.start_tunnel().await {
    //                     error!("TUN tunnel error: {:?}", e);
    //                 }
    //             });
    //         }
    //
    //         Ok(())
    //     }
    //
    //     pub fn stop(&mut self) -> Result<(), VPNError> {
    //         self.inner.stop()
    //     }
    //
    //     pub fn is_running(&self) -> bool {
    //         self.inner.is_running()
    //     }
    // }

    // Android-specific JNI interface
    #[cfg(target_os = "android")]
    pub mod android {
        use std::ffi::{c_char, CStr};
        use jni::JNIEnv;
        use super::*;
        // use jni::JNIEnv;
        use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
        use jni::sys::{jboolean, jint, jlong, jobject};
        use log::LevelFilter;
        use crate::mobile_tun_device::{VPNStatus, TunDeviceConfig, VPNStatusCode};


        pub fn init_logging() {
            android_logger::init_once(
                android_logger::Config::default()
                    .with_max_level(LevelFilter::Debug)
                    .with_tag("ShadowsocksVPN"),
            );
        }

        #[no_mangle]
        pub extern "system" fn Java_com_icegatevpn_client_service_ShadowsocksVPN__isRunning(
            _env: JNIEnv,
            _: JClass,
            ptr: jlong
        ) -> bool {
            if ptr == 0 {
                return false;
            }
            let vpn = unsafe { &*(ptr as *mut ShadowsocksVPN) };
            vpn.is_running()
        }

        #[no_mangle]
        pub extern "system" fn Java_com_icegatevpn_client_service_ShadowsocksVPN_stop(
            _env: JNIEnv,
            _: JClass,
            ptr: jlong
        ) -> bool {
            if ptr == 0 {
                return false;
            }
            true
        }

        #[no_mangle]
        pub extern "system" fn Java_com_icegatevpn_client_service_ShadowsocksVPN_create(
            mut env: JNIEnv,
            _: JClass,
            config: JString,
            fd: jint,
        ) -> jlong {

            init_logging();

            let config_str: String = match env.get_string(&config) {
                Ok(s) => s.into(),
                Err(_) => return 0,
            };

                // Create runtime for async operations
            let runtime = match Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    error!("Failed to create runtime: {:?}", e);
                    return 0;
                }
            };

            // Load config
            let config = match Config::load_from_str(&config_str, ConfigType::Local) {
                Ok(c) => c,
                Err(e) => {
                    error!("<< Failed to load config: {:?}", e);
                    return 0;
                }
            };

            // Create TUN device configuration
            // This sets up a default configuration that should work for most Android VPN setups
            let tun_config = TunDeviceConfig {
                fd: fd as i32,
                address: "10.1.10.2/24".parse().unwrap(),  // VPN interface address
                destination: Some("0.0.0.0/0".parse().unwrap()), // Route all traffic
                mtu: Some(1500),
            };

            // Create TUN device using runtime to handle async operations
            let mut tun = match runtime.block_on(async {
                MobileTunDevice::new(tun_config, config).await
            }) {
                Ok(tun) => tun,
                Err(e) => {
                    error!("<< Failed to create TUN device: {:?}", e);
                    return 0;
                }
            };

            // Box both the runtime and TUN device together
            let state = Box::new((runtime, tun));
            Box::into_raw(state) as jlong
        }

        #[no_mangle]
        pub extern "system" fn Java_com_icegatevpn_client_service_ShadowsocksVPN_run(
            _: JClass,
            ptr: jlong,
        ) -> jlong {

            debug!("<< called start: ptr={:?}", ptr);
            if ptr == 0 {
                return VPNStatusCode::Error.tou8() as jlong;
            }

            let state = unsafe { &mut *(ptr as *mut (Runtime, MobileTunDevice)) };
            let (runtime, tun) = state;

            debug!("<< Starting TUN device");
            let _ = runtime.block_on(async {
                tun.start_tunnel().await
            });
            let status = tun.get_status();
            status.code.tou8() as jlong
        }
    }

    // iOS-specific interface
    #[cfg(target_os = "ios")]
    pub mod ios {
        use super::*;
        use std::ffi::{c_char, CStr};

        #[no_mangle]
        pub extern "C" fn ss_vpn_create(config_json: *const c_char, fd: i32) -> *mut MobileVPN {
            let config_str = unsafe {
                if config_json.is_null() {
                    return std::ptr::null_mut();
                }
                match CStr::from_ptr(config_json).to_str() {
                    Ok(s) => s,
                    Err(_) => return std::ptr::null_mut(),
                }
            };

            let mut vpn = match MobileVPN::new(Config::load_from_str(config_str, ConfigType::Local).unwrap()) {
                Ok(vpn) => vpn,
                Err(_) => return std::ptr::null_mut(),
            };

            if vpn.setup_tun(fd).is_err() {
                return std::ptr::null_mut();
            }

            Box::into_raw(Box::new(vpn))
        }

        #[no_mangle]
        pub extern "C" fn ss_vpn_start(vpn: *mut MobileVPN) -> bool {
            let vpn = unsafe {
                if vpn.is_null() {
                    return false;
                }
                &mut *vpn
            };
            vpn.start().is_ok()
        }
    }
}
