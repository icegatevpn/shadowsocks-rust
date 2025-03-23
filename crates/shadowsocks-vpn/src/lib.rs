use std::cell::RefCell;

#[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
mod mobile_device_manager;
#[cfg(any(target_os = "ios", target_os = "tvos"))]
use std::ffi::c_longlong;

// Thread-local storage for error messages
thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

#[cfg(not(target_os = "android"))]
fn set_last_error<E: std::fmt::Display>(err: E) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(err.to_string());
    });
}

#[cfg(target_os = "macos")]
mod macos_tun_device;
#[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
mod mobile_tun_device;
#[cfg(target_os = "windows")]
pub mod windows_tun_device;

use log::LevelFilter;
#[cfg(not(target_os = "android"))]
use log::error;
use serde_json::Value;
#[cfg(not(target_os = "android"))]
use std::ffi::{c_char, CString};
use std::ffi::CStr;
#[cfg(not(target_os = "android"))]
use std::ptr::{self};
use std::str::FromStr;
use tokio::runtime::Runtime;

#[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
use crate::mobile_device_manager::MobileDeviceManager;
#[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
use crate::mobile_tun_device::MobileTunDevice;

#[cfg(target_os = "macos")]
use crate::macos_tun_device::MacOSTunDevice;
#[cfg(target_os = "windows")]
use crate::windows_tun_device::WindowsTunDevice;

// Opaque type for the VPN context
use tokio::task::JoinHandle;
use shadowsocks_service::my_debug;

// Opaque type for the VPN context
#[repr(C)]
pub struct VpnContext {
    config: String,
    runtime: Runtime,
    #[cfg(any(target_os = "android"))]
    device: MobileDeviceManager,
    #[cfg(target_os = "macos")]
    device: MacOSTunDevice,
    #[cfg(target_os = "windows")]
    device: WindowsTunDevice,
    vpn_task: Option<JoinHandle<std::io::Result<()>>>,
    #[cfg(any(target_os = "ios", target_os = "tvos"))]
    tun_device: MobileTunDevice,
}

#[repr(C)]
#[derive(Debug)]
pub enum VpnError {
    ConfigError = 1,
    RuntimeError = 2,
    DeviceError = 3,
}

#[no_mangle]
#[cfg(not(target_os = "android"))]
pub extern "C" fn vpn_last_error() -> *mut c_char {
    let error_msg = LAST_ERROR
        .with(|e| e.borrow().clone())
        .unwrap_or_else(|| "No error".to_string());

    match CString::new(error_msg) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub extern "C" fn vpn_create(config_json: *const c_char) -> *mut VpnContext {
    if config_json.is_null() {
        return ptr::null_mut();
    }

    // Convert C string to Rust string
    let config_str = unsafe {
        match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    // Create runtime
    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            set_last_error(format!("Failed to create runtime: {}", e));
            return ptr::null_mut();
        }
    };

    #[cfg(target_os = "macos")]
    let device = match MacOSTunDevice::new() {
        Ok(d) => d,
        Err(_) => return ptr::null_mut(),
    };

    #[cfg(target_os = "windows")]
    let device = match WindowsTunDevice::new() {
        Ok(d) => d,
        Err(_) => return ptr::null_mut(),
    };

    // Create context
    let context = Box::new(VpnContext {
        config: config_str.to_string(),
        runtime,
        device,
        vpn_task: None,
    });

    Box::into_raw(context)
}

#[no_mangle]
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub extern "C" fn vpn_start(context: *mut VpnContext) -> bool {
    let context = match unsafe { context.as_mut() } {
        Some(c) => c,
        None => {
            set_last_error("Null context pointer");
            return false;
        }
    };

    // Create handle for spawning the VPN task
    let handle = context.runtime.spawn(async {
        // let result = context.device.start_tunnel().await;
        #[cfg(target_os = "android")]
        return Err(VpnError::RuntimeError);

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        return context.device.start(context.config.clone()).await;
    });

    // Store handle for potential cancellation/cleanup
    context.runtime.spawn(async move {
        match handle.await {
            Ok(Ok(_)) => {
                my_debug!("VPN service running successfully");
            }
            Ok(Err(e)) => {
                let err_msg = format!("VPN service error: {:?}", e);
                error!("{}", err_msg);
                set_last_error(err_msg);
            }
            Err(e) => {
                let err_msg = format!("VPN task join error: {}", e);
                error!("{}", err_msg);
                set_last_error(err_msg);
            }
        }
    });

    true
}

#[no_mangle]
#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "macos", target_os = "windows"))]
pub extern "C" fn vpn_stop(context: *mut VpnContext) -> bool {
    let context = match unsafe { context.as_mut() } {
        Some(c) => c,
        None => {
            set_last_error("Null context pointer");
            return false;
        }
    };

    // Abort any running VPN task
    if let Some(task) = context.vpn_task.take() {
        task.abort();
        return true;
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    match context.runtime.block_on(async { context.device.stop().await }) {
        Ok(_) => true,
        Err(e) => {
            let err_msg = format!("Failed to stop VPN: {}", e);
            error!("{}", err_msg);
            set_last_error(err_msg);
            false
        }
    }

    #[cfg(any(target_os = "ios", target_os = "tvos", target_os = "android"))]
    match context.runtime.block_on(async { MobileDeviceManager::stop().await }) {
        Ok(_) => true,
        Err(e) => {
            let err_msg = format!("Failed to stop VPN: {}", e);
            error!("{}", err_msg);
            set_last_error(err_msg);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn vpn_destroy(context: *mut VpnContext) {
    if !context.is_null() {
        unsafe {
            drop(Box::from_raw(context));
        }
    }
}
#[cfg(any(target_os = "ios", target_os = "tvos"))]
#[no_mangle]
pub unsafe extern "C" fn create_vpn(config_json: *const c_char, fd: i32) -> *mut VpnContext {
    ios::create_vpn(config_json, fd)
}

#[cfg(any(target_os = "ios", target_os = "tvos"))]
#[no_mangle]
pub unsafe extern "C" fn start_vpn(context: *mut VpnContext) -> c_longlong {
    ios::start_vpn(context).unwrap_or_else(|_| -1)
}

#[cfg(any(target_os = "ios", target_os = "tvos"))]
#[no_mangle]
pub unsafe extern "C" fn stop_vpn(context: *mut VpnContext) -> c_longlong {
    error!("<<< STOP THIS!!");
    // ios::stop_vpn(context).unwrap_or_else(|e| -1)
    7
}

#[cfg(any(target_os = "ios", target_os = "tvos"))]
#[no_mangle]
pub unsafe extern "C" fn get_status(context: *mut VpnContext) -> c_longlong {
    ios::get_status(context)
}

#[cfg(any(target_os = "ios", target_os = "tvos"))]
#[no_mangle]
pub extern "C" fn test_logging() {
    ios::test_logging()
}

#[cfg(any(target_os = "ios", target_os = "tvos"))]
pub mod ios {
    use crate::mobile_tun_device::{MobileTunDevice, VPNStatusCode};
    use crate::{get_log_lvl, VpnContext};
    use futures::executor::block_on;
    use oslog::OsLogger;
    use shadowsocks_service::{my_debug, my_error};
    use std::ffi::{c_char, c_longlong};
    use std::ptr;
    use tokio::runtime::Runtime;

    #[derive(Debug)]
    pub enum VPNError {
        NullPointer(String),
        InvalidUtf8(String),
        Other(&'static str),
    }
    pub fn test_logging() {
        init_logging(&"".to_string());
    }

    fn init_logging(config: &str) {
        // Initialize once
        static INIT: std::sync::Once = std::sync::Once::new();

        INIT.call_once(|| {
            // Create logger with subsystem and category
            let lvl = get_log_lvl(config);
            let logger = OsLogger::new("com.IceGate.vpn").level_filter(lvl);

            // Set as global logger
            log::set_boxed_logger(Box::new(logger))
                .map(|()| log::set_max_level(lvl))
                .expect("Failed to initialize logging");
        });
    }

    #[macro_export]
    macro_rules! c_str {
        ($ptr:expr) => {{
            if $ptr.is_null() {
                Err(VPNError::NullPointer("null C string pointer".into()))
            } else {
                unsafe {
                    match std::ffi::CStr::from_ptr($ptr).to_str() {
                        Ok(s) => Ok(s),
                        Err(e) => Err(VPNError::InvalidUtf8(format!("{}", e))),
                    }
                }
            }
        }};
    }
    pub fn create_vpn(config_json: *const c_char, fd: i32) -> *mut VpnContext {
        my_debug!("Creating VPN");
        let config_str = c_str!(config_json).expect("<< failed to parse config");
        init_logging(config_str);
        // Create runtime for async operations
        let runtime = match Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                my_error!("Failed to create runtime: {}", e);
                return ptr::null_mut();
            }
        };

        // Create TUN device using runtime to handle async operations
        let tun_device = match runtime.block_on(async { MobileTunDevice::new(fd, config_str).await }) {
            Ok(tun) => tun,
            Err(e) => {
                my_error!("Failed to create TUN device: {:?}", e);
                return ptr::null_mut();
            }
        };
        // Allocate VPN context
        let context = Box::new(VpnContext {
            config: config_str.to_string(),
            runtime,
            tun_device,
            vpn_task: None,
        });

        Box::into_raw(context)
    }

    pub unsafe fn start_vpn(context: *mut VpnContext) -> Result<i64, VPNError> {
        my_debug!("Start VPN!!!!");
        let context = &mut *context;
        let runtime_handle = context.runtime.handle().clone();
        // Spawn the tunnel task into the background
        runtime_handle.spawn(async move {
            my_debug!("Starting TUN device in background task ....");
            match context.tun_device.start_tunnel().await {
                Ok(_) => {
                    my_debug!("TUN tunnel completed successfully");
                    VPNStatusCode::Connected.tou8() as i64
                }
                Err(e) => {
                    my_error!("TUN tunnel error: {:?}", e);
                    VPNStatusCode::Error.tou8() as i64
                }
            }
        });

        Ok(VPNStatusCode::Connecting.tou8() as i64)
    }

    // todo haven't quite got working yet
    pub unsafe fn stop_vpn(context: *mut VpnContext) -> Result<i64, VPNError> {
        let context = &mut *context;
        block_on(async {
            my_debug!("stopping TUN device...");
            match context.tun_device.cancel().await {
                Ok(_) => {
                    my_debug!("TUN stopped successfully");
                    Ok(VPNStatusCode::Started.tou8() as i64)
                }
                Err(e) => {
                    my_error!("Failed to stop TUN device: {:?}", e);
                    Err(VPNError::Other("Failed to stop Shadowsocks service"))
                }
            }
        })
    }

    pub unsafe fn get_status(context: *mut VpnContext) -> c_longlong {
        let context = &mut *context;
        context.runtime.block_on(async {
            let status = context.tun_device.get_status_async().await;
            status.code.tou8() as c_longlong
        })
    }
}

fn get_log_lvl(config: &str) -> LevelFilter {
    let v: Value = match serde_json::from_str(config) {
        Ok(v) => v,
        Err(_) => return LevelFilter::Debug,
    };
    LevelFilter::from_str(v["rust_log_lvl"].as_str().unwrap_or("Debug")).unwrap_or(LevelFilter::Debug)
}

#[cfg(target_os = "android")]
pub mod android {
    use super::*;
    use jni::objects::{JClass, JString};
    use jni::sys::{jboolean, jint, jlong};
    use jni::JNIEnv;
    use log::{debug, error, info, LevelFilter};

    pub fn init_logging(level: Option<LevelFilter>) {
        let level = level.unwrap_or_else(|| LevelFilter::Debug);

        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(level)
                .with_tag("ShadowsocksVPN"),
        );
    }

    use serde_json::Value;

    #[no_mangle]
    pub extern "system" fn Java_com_icegatevpn_client_vpn_IcegateVpnService_create(
        mut env: JNIEnv,
        _: JClass,
        config: JString,
        fd: jint,
    ) -> jlong {
        let config_str: String = match env.get_string(&config) {
            Ok(s) => s.into(),
            Err(_) => "".into(),
        };
        let lvl_filter = get_log_lvl(&config_str);
        init_logging(Some(lvl_filter));

        // Create and initialize the singleton instance
        // Initialize directly without JNI frame
        match futures::executor::block_on(async { MobileDeviceManager::initialize(&config_str, fd as i32).await }) {
            Ok(_) => 1, // Return non-zero to indicate success
            Err(e) => {
                error!("Failed to initialize VPN: {}", e);
                0
            }
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_icegatevpn_client_vpn_IcegateVpnService_start(
        _: JNIEnv,
        _: JClass,
        _: jlong,
    ) -> jlong {
        match futures::executor::block_on(async { MobileDeviceManager::start().await }) {
            Ok(status) => status,
            Err(e) => {
                error!("Failed to start VPN: {}", e);
                -1
            }
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_icegatevpn_client_vpn_IcegateVpnService_checkStatus(
        _env: JNIEnv,
        _: JClass,
        _ptr: jlong,
    ) -> jlong {
        debug!("Shadowsocks VPN check isRunning");
        match futures::executor::block_on(async { MobileDeviceManager::get_status().await }) {
            Ok(status) => status.code.tou8() as i64,
            Err(_) => -1,
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_icegatevpn_client_vpn_IcegateVpnService_stop(
        _: JNIEnv,
        _: JClass,
        _: jlong,
    ) -> jboolean {
        info!("Stopping VPN service from JNI");
        match futures::executor::block_on(async { MobileDeviceManager::stop().await }) {
            Ok(_) => {
                info!("VPN service successfully stopped");
                true as jboolean
            }
            Err(e) => {
                error!("Failed to stop VPN service: {}", e);
                false as jboolean
            }
        }
    }
}
