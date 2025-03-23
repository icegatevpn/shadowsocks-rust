//! Shadowsocks service command line utilities

pub mod allocator;
pub mod config;
#[cfg(unix)]
pub mod daemonize;
pub mod error;
#[cfg(feature = "logging")]
pub mod logging;
pub mod monitor;
pub mod password;
pub mod service;
pub mod sys;
pub mod vparser;

/// Build timestamp in UTC
pub const BUILD_TIME: &str = build_time::build_time_utc!();

/// shadowsocks version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const TAG: &str = "<<";
#[macro_export]
macro_rules! my_error {
    ($($arg:tt)*) => {
        log!("ERROR", format!("{} {}",TAG, $($arg)*));
    };
}
#[macro_export]
macro_rules! my_log {
    ($level:expr, $($arg:tt)*) => {
        println!("[{}] {}", $level, format!("{} {}",TAG, $($arg)*));
    };
}
#[macro_export]
macro_rules! my_debug {
    ($($arg:tt)*) => {
        log!("DEBUG", format!("{} {}",TAG, $($arg)*));
    };
}
#[macro_export]
macro_rules! my_info {
    ($($arg:tt)*) => {
        log!("INFO", format!("{} {}",TAG, $($arg)*));
    };
}
#[macro_export]
macro_rules! my_warn {
    ($($arg:tt)*) => {
        log!("WARN", format!("{} {}",TAG,$($arg)*));
    };
}
