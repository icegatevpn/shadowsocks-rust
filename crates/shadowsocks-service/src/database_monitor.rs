use tokio::time::{sleep, Duration};
use rusqlite::{Connection, Error as RusqliteError};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use crate::mysql_db::ServerConfig;

// Structure to track the last check timestamp
#[derive(Debug)]
struct LastCheck {
    timestamp: i64,
}

// Generic trait for handling database updates
pub trait DatabaseUpdateHandler: Send + Sync {
    fn handle_update(&self, record: ServerConfig) -> Result<(), RusqliteError>;
}

pub struct DatabaseMonitor {
    db_path: String,
    check_interval: Duration,
    handler: Arc<dyn DatabaseUpdateHandler>,
}

/*
    This is Interesting, not sure if I need it, but worth holding onto.
 */
impl DatabaseMonitor {
    pub fn new(db_path: String, check_interval: Duration, handler: Arc<dyn DatabaseUpdateHandler>) -> Self {
        DatabaseMonitor {
            db_path,
            check_interval,
            handler,
        }
    }

    pub async fn start(&self) {
        info!("Starting database monitor service");

        let last_check = Arc::new(Mutex::new(LastCheck {
            timestamp: chrono::Utc::now().timestamp(),
        }));

        loop {
            if let Err(err) = self.check_for_updates(Arc::clone(&last_check)).await {
                error!("Error checking for updates: {}", err);
            }

            sleep(self.check_interval).await;
        }
    }

    async fn check_for_updates(&self, last_check: Arc<Mutex<LastCheck>>) -> Result<(), RusqliteError> {
        // Open a new connection for this check
        let conn = Connection::open(&self.db_path)?;

        let timestamp = {
            let last = last_check.lock().await;
            last.timestamp
        };

        // Query for new or updated records since last check
        let mut stmt = conn.prepare(
            "SELECT ip_address, port, method, mode, key, active,
                    remarks, timeout_seconds, tcp_weight, udp_weight,
                    plugin, plugin_opts, plugin_args,
                    created_at, updated_at
             FROM servers
             WHERE updated_at > datetime(?1, 'unixepoch')
             OR created_at > datetime(?1, 'unixepoch')"
        )?;

        let server_iter = stmt.query_map([timestamp], |row| {
            Ok(ServerConfig {
                ip_address: row.get(0)?,
                port: row.get(1)?,
                method: row.get(2)?,
                mode: row.get(3)?,
                key: row.get(4)?,
                active: row.get(5)?,
                remarks: row.get(6)?,
                timeout: row.get::<_, Option<i64>>(7)?
                    .map(|secs| Duration::from_secs(secs as u64)),
                tcp_weight: row.get(8)?,
                udp_weight: row.get(9)?,
                plugin: row.get(10)?,
                plugin_opts: row.get(11)?,
                plugin_args: row.get(12)?,
                created_at: row.get(13)?,
                updated_at: row.get(14)?,
                users: Vec::new(), // We'll populate this if needed
            })
        })?;

        // Process each updated record
        for server_result in server_iter {
            match server_result {
                Ok(server) => {
                    debug!("Processing update for server port {}", server.port);
                    if let Err(e) = self.handler.handle_update(server) {
                        error!("Error handling server update: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error reading server record: {}", e);
                }
            }
        }

        // Update the last check timestamp
        let now = chrono::Utc::now().timestamp();
        {
            let mut last = last_check.lock().await;
            last.timestamp = now;
        }

        Ok(())
    }
}

// Example handler implementation
pub struct ServerUpdateHandler {
    // Add any necessary fields for handling updates
}

impl DatabaseUpdateHandler for ServerUpdateHandler {
    fn handle_update(&self, server: ServerConfig) -> Result<(), RusqliteError> {
        info!("Handling update for server port {}", server.port);
        // Implement your update handling logic here
        // For example:
        // - Restart the server with new configuration
        // - Update the running server's settings
        // - Notify other parts of the system
        Ok(())
    }
}

// Example usage:
pub async fn start_database_monitor(db_path: String) {
    let handler = Arc::new(ServerUpdateHandler {});
    let monitor = DatabaseMonitor::new(
        db_path,
        Duration::from_secs(5), // Check every 5 seconds
        handler,
    );

    monitor.start().await;
}