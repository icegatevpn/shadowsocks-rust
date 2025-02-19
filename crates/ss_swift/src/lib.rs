use std::ffi::{c_char, CStr, CString, c_void};
use std::os::raw::c_int;
use std::ptr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::runtime::Runtime;

lazy_static::lazy_static! {
    static ref HANDLER: Mutex<Option<HandlerHolder>> = Mutex::new(None);
}

// Define a function pointer type for calling Swift's handle method
type HandleFn = extern "C" fn(*mut c_void, *const c_char);
type WriteFn = extern "C" fn(*mut c_void, *const c_void, c_int);

// Wrapper struct to store the Swift handler pointer and callback function
struct HandlerHolder {
    handler_ptr: *mut c_void,
    handler_fn: HandleFn,
    write_fn: WriteFn,
}
unsafe impl Send for HandlerHolder {}
unsafe impl Sync for HandlerHolder {}

#[no_mangle]
pub extern "C" fn with_handler(handler_ptr: *mut c_void, handler_fn: HandleFn, write_fn: WriteFn) {
    let mut handler_guard = HANDLER.lock().unwrap();
    *handler_guard = Some(HandlerHolder {
        handler_ptr,
        handler_fn,
        write_fn
    });
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Runtime::new().unwrap()
    })
}
#[no_mangle]
pub extern "C" fn initialize_runtime() {
    get_runtime(); // This will create the runtime if it doesn't exist
}
#[no_mangle]
pub extern "C" fn send_binary_data() {
    let handler_guard = HANDLER.lock().unwrap();
    if let Some(handler) = &*handler_guard {
        let data = vec![0x01, 0x02, 0x03, 0x04]; // Example binary data
        let length = data.len() as c_int;
        unsafe {
            (handler.write_fn)(handler.handler_ptr, data.as_ptr() as *const c_void, length);
        };
        drop(handler_guard);
        get_runtime().spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let handler_guard = HANDLER.lock().unwrap();
            if let Some(handler) = &*handler_guard {
                let data = vec![0x01, 0x02, 0x03, 0x04, 0x04, 0x04, 0x04, 0x04];
                let length = data.len() as c_int;
                println!("did something..");
                (handler.write_fn)(handler.handler_ptr, data.as_ptr() as *const c_void, length);
            }
        });
    }
}

#[no_mangle]
pub extern "C" fn trigger_event(message: *const c_char) {
    let handler_guard = HANDLER.lock().unwrap();
    if let Some(handler) = &*handler_guard {
        let message_str = unsafe { CStr::from_ptr(message).to_str().unwrap() };
        println!("Rust received: {}", message_str);
        let c_message = CString::new(message_str).unwrap();
        unsafe {
            (handler.handler_fn)(handler.handler_ptr, c_message.as_ptr());
        }
    }
}

#[no_mangle]
pub extern "C" fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[no_mangle]
pub extern "C" fn append(first: *const c_char, second: *const c_char) -> *mut c_char {
    // Safety checks
    if first.is_null() || second.is_null() {
        return ptr::null_mut();
    }

    // Convert C strings to Rust strings
    let first_str = unsafe { CStr::from_ptr(first) }.to_str().unwrap_or("");
    let second_str = unsafe { CStr::from_ptr(second) }.to_str().unwrap_or("");

    // Do the string operation
    let result = format!("{} :: {}", first_str, second_str);

    // Convert back to C string
    match CString::new(result) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

// Helper function to free the string memory allocated by Rust
#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    unsafe {
        if !s.is_null() {
            let ss = CString::from_raw(s);
            drop(ss);
        }
    }
}
