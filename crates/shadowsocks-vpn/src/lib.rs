use std::cell::RefCell;

#[cfg(any(target_os = "android", target_os = "ios"))]
mod mobile_singleton;

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
#[cfg(target_os = "android")]
mod mobile_tun_device;
#[cfg(target_os = "windows")]
pub mod windows_tun_device;

#[cfg(target_os = "android")]
use crate::mobile_singleton::MobileDeviceManager;
#[cfg(not(target_os = "android"))]
use log::{debug, error, info};
#[cfg(not(target_os = "android"))]
use std::ptr::{self, NonNull};
#[cfg(not(target_os = "android"))]
use std::{
    ffi::{c_char, CStr, CString},
    sync::Arc,
};
use tokio::runtime::Runtime;

#[cfg(target_os = "macos")]
use crate::macos_tun_device::MacOSTunDevice;
#[cfg(target_os = "windows")]
use crate::windows_tun_device::WindowsTunDevice;
#[cfg(not(target_os = "android"))]
use shadowsocks_service::config::{Config, ConfigType};

// Opaque type for the VPN context
use tokio::task::JoinHandle;

// Opaque type for the VPN context
#[repr(C)]
pub struct VpnContext {
    runtime: Runtime,
    #[cfg(target_os = "android")]
    device: MobileDeviceManager,
    #[cfg(target_os = "macos")]
    device: MacOSTunDevice,
    #[cfg(target_os = "windows")]
    device: WindowsTunDevice,
    vpn_task: Option<JoinHandle<std::io::Result<()>>>,
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
#[cfg(not(target_os = "android"))]
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

    // Parse config
    let config = match Config::load_from_str(config_str, ConfigType::Local) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("Failed to parse config: {}", e));
            return ptr::null_mut();
        }
    };

    #[cfg(target_os = "macos")]
    let device = match MacOSTunDevice::new(config) {
        Ok(d) => d,
        Err(_) => return ptr::null_mut(),
    };

    #[cfg(target_os = "windows")]
    let device = match WindowsTunDevice::new(config) {
        Ok(d) => d,
        Err(_) => return ptr::null_mut(),
    };

    // Create context
    let context = Box::new(VpnContext {
        runtime,
        device,
        vpn_task: None,
    });

    Box::into_raw(context)
}

#[no_mangle]
#[cfg(not(target_os = "android"))]
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
        return context.device.start().await;
        // let result = context.device.start().await;

        // result
    });

    // Store handle for potential cancellation/cleanup
    context.runtime.spawn(async move {
        match handle.await {
            Ok(Ok(_)) => {
                debug!("VPN service running successfully");
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
#[cfg(not(target_os = "android"))]
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
    }

    // Stop the VPN device
    match context.runtime.block_on(async {
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        context.device.stop().await
    }) {
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

#[cfg(target_os = "android")]
pub mod android {
    use std::str::FromStr;
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
    fn get_log_lvl(config: &String) -> LevelFilter {
        let v: Value = match serde_json::from_str(config) {
            Ok(v) => v,
            Err(_) => return LevelFilter::Debug,
        };
        LevelFilter::from_str(v["rust_log_lvl"].as_str().unwrap_or("Debug"))
            .unwrap_or(LevelFilter::Debug)
    }

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

        let config_str: String = match env.get_string(&config) {
            Ok(s) => s.into(),
            Err(_) => return 0,
        };
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
        match futures::executor::block_on(async { MobileDeviceManager::stop().await }) {
            Ok(_) => true as jboolean,
            Err(_) => false as jboolean,
        }
    }
}
