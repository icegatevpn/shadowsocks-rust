//! Service launchers

pub mod genkey;
#[cfg(feature = "local")]
pub mod local;
#[cfg(feature = "manager")]
pub mod manager;
#[cfg(feature = "server")]
pub mod server;
mod web_service;
mod domain_connection;
