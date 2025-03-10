//! Service launchers

pub mod genkey;
#[cfg(feature = "local")]
pub mod local;
#[cfg(feature = "manager")]
pub mod manager;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "manager")]
mod web_service;
mod domain_connection;
mod key_generator;
