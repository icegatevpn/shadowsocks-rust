use std::ffi::{c_char, CStr, CString, c_void};
use std::ptr;
// use std::os::raw::{c_char, c_void};
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref HANDLER: Mutex<Option<Box<dyn Handler + Send>>> = Mutex::new(None);
}

pub trait Handler {
    fn handle(&self, message: &str);
}

// Define a C function type for the handler
type HandleFn = extern "C" fn(*const c_char);

#[no_mangle]
pub extern "C" fn with_handler(handler: extern "C" fn(*const c_char)) {
    let message = CString::new("Hello from Rust!").unwrap();
    handler(message.as_ptr());
}

#[no_mangle]
pub extern "C" fn trigger_event(message: *const c_char) {
    let message_str = unsafe { CStr::from_ptr(message).to_str().unwrap() };
    println!("Rust received: {}", message_str);
}

#[no_mangle]
pub extern "C" fn dyn_with_handler(handler: HandleFn) {
    struct SwiftHandler {
        callback: HandleFn,
    }

    impl Handler for SwiftHandler {
        fn handle(&self, message: &str) {
            let c_message = CString::new(message).unwrap();
            (self.callback)(c_message.as_ptr());
        }
    }

    let mut handler_guard = HANDLER.lock().unwrap();
    *handler_guard = Some(Box::new(SwiftHandler { callback: handler }));
}

#[no_mangle]
pub extern "C" fn dyn_trigger_event(message: *const c_char) {
    let handler_guard = HANDLER.lock().unwrap();
    if let Some(handler) = &*handler_guard {
        let message_str = unsafe { CStr::from_ptr(message).to_str().unwrap() };
        handler.handle(message_str);
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
