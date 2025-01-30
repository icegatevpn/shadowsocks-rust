use std::ffi::{c_char, CStr, CString};
use std::ptr;

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
