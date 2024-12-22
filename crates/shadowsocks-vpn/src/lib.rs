
use std::sync::Arc;
use tokio::runtime::Runtime;
// use shadowsocks::config::Config as SSConfig;
use shadowsocks_service::{config::{Config, ConfigType}, run_local};
// use futures::future::{self, Either};
use tokio::sync::oneshot;
use std::sync::atomic::{AtomicBool, Ordering};
use log::{debug, error, warn};
use futures::pin_mut;

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

impl ShadowsocksVPN {
    pub fn new(config: Config) -> Result<Self, VPNError> {
        // Validate config
        if config.check_integrity().is_err() {
            return Err(VPNError::ConfigError("Invalid configuration".into()));
        }

        let runtime = Runtime::new()
            .map_err(|e| VPNError::RuntimeError(e.to_string()))?;

        Ok(Self {
            runtime,
            config,
            running: Arc::new(AtomicBool::new(false)),
            shutdown_tx: None,
        })
    }

    pub fn start(&mut self) -> Result<(), VPNError> {
        if self.running.load(Ordering::Acquire) {
            warn!("VPN already running");
            return Ok(());
        }
        let config = self.config.clone();
        let running = self.running.clone();
        // Create a shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn the server in the runtime
        self.runtime.spawn(async move {
            running.store(true, Ordering::Release);

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

#[cfg(target_os = "ios")]
mod ios {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;
    use shadowsocks_service::config::Config;

    #[no_mangle]
    pub extern "C" fn ss_vpn_create(config_json: *const c_char) -> *mut ShadowsocksVPN {
        let config_str = unsafe {
            if config_json.is_null() {
                return std::ptr::null_mut();
            }
            match CStr::from_ptr(config_json).to_str() {
                Ok(s) => s,
                Err(_) => return std::ptr::null_mut(),
            }
        };

        // Use shadowsocks' built-in config loading
        let config = match Config::load_from_str(config_str, ConfigType::Local) {
            Ok(c) => c,
            Err(_) => return std::ptr::null_mut(),
        };

        match ShadowsocksVPN::new(config) {
            Ok(vpn) => Box::into_raw(Box::new(vpn)),
            Err(_) => std::ptr::null_mut()
        }
    }

    #[no_mangle]
    pub extern "C" fn ss_vpn_start(vpn: *mut ShadowsocksVPN) -> bool {
        let vpn = unsafe {
            if vpn.is_null() {
                return false;
            }
            &mut *vpn
        };
        vpn.start().is_ok()
    }

    #[no_mangle]
    pub extern "C" fn ss_vpn_stop(vpn: *mut ShadowsocksVPN) -> bool {
        let vpn = unsafe {
            if vpn.is_null() {
                return false;
            }
            &mut *vpn
        };
        vpn.stop().is_ok()
    }

    #[no_mangle]
    pub extern "C" fn ss_vpn_destroy(vpn: *mut ShadowsocksVPN) {
        if !vpn.is_null() {
            unsafe {
                let _ = Box::from_raw(vpn);
            }
        }
    }

    #[no_mangle]
    pub extern "C" fn ss_vpn_is_running(vpn: *const ShadowsocksVPN) -> bool {
        let vpn = unsafe {
            if vpn.is_null() {
                return false;
            }
            &*vpn
        };
        vpn.is_running()
    }
}

// FFI interface for Android
#[cfg(target_os = "android")]
mod android {
    use super::*;
    use jni::JNIEnv;
    use jni::objects::{JClass, JString};
    use jni::sys::jlong;
    use android_logger::Config as LogConfig;
    use log::{Level, LevelFilter};
    use ndk_context::AndroidContext;

    pub fn init_logging() {
        android_logger::init_once(
            LogConfig::default()
                .with_max_level(LevelFilter::Debug)
                .with_tag("ShadowsocksVPN"),
        );
    }

    #[no_mangle]
    #[allow(non_snake_case)]
    pub extern "system" fn Java_com_example_ShadowsocksVPN_create(
        mut env: JNIEnv,
        _: JClass,
        config: JString
    ) -> jlong {
        // Initialize logging first
        init_logging();

        let config_str: String = match env.get_string(&config) {
            Ok(s) => s.into(),
            Err(_) => return 0,
        };

        // Use shadowsocks' built-in config loading
        let config = match Config::load_from_str(&config_str, ConfigType::Local) {
            Ok(c) => c,
            Err(_) => return 0,
        };

        match ShadowsocksVPN::new(config) {
            Ok(vpn) => Box::into_raw(Box::new(vpn)) as jlong,
            Err(_) => 0
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_example_ShadowsocksVPN_start(
        _env: JNIEnv,
        _: JClass,
        ptr: jlong
    ) -> bool {
        if ptr == 0 {
            return false;
        }
        let vpn = unsafe { &mut *(ptr as *mut ShadowsocksVPN) };
        vpn.start().is_ok()
    }

    #[no_mangle]
    pub extern "system" fn Java_com_example_ShadowsocksVPN_stop(
        _env: JNIEnv,
        _: JClass,
        ptr: jlong
    ) -> bool {
        if ptr == 0 {
            return false;
        }
        let vpn = unsafe { &mut *(ptr as *mut ShadowsocksVPN) };
        vpn.stop().is_ok()
    }

    #[no_mangle]
    pub extern "system" fn Java_com_example_ShadowsocksVPN_isRunning(
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
    pub extern "system" fn Java_com_example_ShadowsocksVPN_destroy(
        _env: JNIEnv,
        _: JClass,
        ptr: jlong
    ) {
        if ptr != 0 {
            unsafe {
                let _ = Box::from_raw(ptr as *mut ShadowsocksVPN);
            }
        }
    }
}
