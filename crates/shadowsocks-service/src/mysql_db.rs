use crate::config::{Config, ServerInstanceConfig};
use chrono::{NaiveDateTime, Utc};
use log::{debug, error};
use rusqlite::{
    params,
    Connection, Error as RusqliteError, Error, OptionalExtension, Row,
};
use crate::url_generator::{generate_ssurl};
use rusqlite::hooks::Action;
use serde::{Deserialize, Serialize};
use shadowsocks::config::{Mode, ServerConfig as SSServerConfig, ServerUser, ServerUserManager, ServerWeight};
use shadowsocks::crypto::CipherKind;
use shadowsocks::manager::protocol::AddUser;
use shadowsocks::plugin::PluginConfig;
use shadowsocks::ServerAddr;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub enum DatabaseChange {
    ServerAdded(u32),
    ServerRemoved(u32),
    ServerUpdated(u32),
    UserAdded(String),
    UserRemoved(String),
    UserUpdated(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(rename = "server")]
    pub ip_address: String,
    #[serde(rename = "server_port")]
    pub port: u16,
    pub method: String,
    pub mode: String,
    #[serde(rename = "password")]
    pub key: String,

    // Database only fields
    #[serde(skip_serializing)]
    pub active: bool,

    #[serde(skip_serializing)]
    pub created_at: Option<NaiveDateTime>,
    #[serde(skip_serializing)]
    pub remarks: Option<String>,
    #[serde(skip_serializing)]
    pub timeout: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_weight: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_weight: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_opts: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_args: Option<String>,
    #[serde(skip_serializing)]
    pub updated_at: Option<NaiveDateTime>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<UserConfig>,
}
impl ServerConfig {
    pub fn new(addr: ServerAddr, password: String, method: CipherKind) -> Result<Self, RusqliteError> {
        let (ip_address, port) = match addr {
            ServerAddr::SocketAddr(sock_addr) => (sock_addr.ip().to_string(), sock_addr.port()),
            ServerAddr::DomainName(domain, port) => (domain, port),
        };

        Ok(ServerConfig {
            ip_address,
            port,
            method: method.to_string(),
            mode: Mode::TcpOnly.to_string(), // Default mode
            key: password,
            active: true,
            remarks: None,
            timeout: None,
            tcp_weight: None,
            udp_weight: None,
            plugin: None,
            plugin_opts: None,
            plugin_args: None,
            created_at: Some(Utc::now().naive_utc()),
            updated_at: Some(Utc::now().naive_utc()),
            users: Vec::new(),
        })
    }

    pub fn to_shadowsocks_config(&self) -> Result<SSServerConfig, RusqliteError> {
        let addr = if let Ok(ip) = self.ip_address.parse() {
            ServerAddr::SocketAddr(SocketAddr::new(ip, self.port as u16))
        } else {
            ServerAddr::DomainName(self.ip_address.clone(), self.port as u16)
        };

        let method = self
            .method
            .parse::<CipherKind>()
            .map_err(|e| RusqliteError::InvalidParameterName(format!("Invalid cipher method: {}", e)))?;

        let mut ss_config = SSServerConfig::new(addr, self.key.clone(), method)
            .map_err(|e| RusqliteError::InvalidParameterName(format!("Failed to create server config: {}", e)))?;

        // Set mode
        if let Ok(mode) = self.mode.parse::<Mode>() {
            ss_config.set_mode(mode);
        }

        // Set timeout
        if let Some(timeout) = self.timeout {
            ss_config.set_timeout(timeout);
        }

        // Set weights
        if let (Some(tcp), Some(udp)) = (self.tcp_weight, self.udp_weight) {
            let mut weight = ServerWeight::new();
            weight.set_tcp_weight(tcp);
            weight.set_udp_weight(udp);
            ss_config.set_weight(weight);
        }

        // Set plugin if present
        if let Some(ref plugin) = self.plugin {
            let plugin_config = PluginConfig {
                plugin: plugin.clone(),
                plugin_opts: self.plugin_opts.clone(),
                plugin_args: self
                    .plugin_args
                    .as_ref()
                    .and_then(|args| serde_json::from_str(args).ok())
                    .unwrap_or_default(),
                plugin_mode: Mode::TcpOnly,
            };
            ss_config.set_plugin(plugin_config);
        }

        // Set remarks
        if let Some(ref remarks) = self.remarks {
            ss_config.set_remarks(remarks.clone());
        }

        // Set user manager if there are users
        if !self.users.is_empty() {
            let mut user_manager = ServerUserManager::new();
            for user in &self.users {
                if user.active {
                    match ServerUser::with_encoded_key(user.name.clone(), &user.key) {
                        Ok(ss_user) => {
                            let _ = user_manager.add_user(ss_user);
                        }
                        Err(e) => {
                            return Err(RusqliteError::InvalidParameterName(format!(
                                "Failed to create user {}: {}",
                                user.name, e
                            )));
                        }
                    }
                }
            }
            ss_config.set_user_manager(user_manager);
        }

        Ok(ss_config)
    }
}

#[derive(Debug)]
pub enum KeyError {
    RandomGenerationFailed,
    EncodingFailed,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::RandomGenerationFailed => write!(f, "Failed to generate random bytes"),
            KeyError::EncodingFailed => write!(f, "Failed to encode key"),
        }
    }
}
impl std::error::Error for KeyError {}
/// Generates a 16-byte (128-bit) random key and returns it base64 URL-safe encoded
pub fn generate_manager_key() -> Result<String, KeyError> {
    // Create a buffer for the 16-byte key
    let mut key = vec![0u8; 16];

    // Fill it with random bytes using the OS random number generator
    OsRng
        .try_fill_bytes(&mut key)
        .map_err(|_| KeyError::RandomGenerationFailed)?;

    // Encode using base64 URL-safe encoding
    Ok(URL_SAFE.encode(key))
}

#[derive(Debug, Deserialize)]
pub struct SsUrlParams {
    pub server_address: String,
    pub server_port: u16,
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManagerConfig {
    // manager_tcp_address: Option<String>,
    manager_port: u16,
    #[serde(rename = "manager_address")]
    manager_sock_address: String,
    servers: Vec<ServerConfig>,
    // 16 bytes, 128 bits, base64 url safe key
    url_key: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserConfig {
    #[serde(skip_serializing)]
    pub id: Option<i64>,
    pub name: String,
    #[serde(rename = "password")]
    pub key: String,
    #[serde(skip_serializing)]
    pub server_port: u16,
    #[serde(skip_serializing)]
    pub active: bool,
    #[serde(skip_serializing)]
    pub remarks: Option<String>,
    #[serde(skip_serializing)]
    pub created_at: Option<NaiveDateTime>,
    #[serde(skip_serializing)]
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug)]
pub struct Database {
    pub conn: Connection,
}
#[allow(dead_code)]
pub struct DatabaseWithHooks {
    pub conn: Connection,
    change_tx: broadcast::Sender<DatabaseChange>,
}

// todo: experimental! If I don't use this, I can remove the 'hooks' feature requirement.
#[allow(dead_code)]
impl DatabaseWithHooks {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<(Self, broadcast::Receiver<DatabaseChange>), RusqliteError> {
        let conn = Connection::open(path)?;
        let (tx, rx) = broadcast::channel(100); // Buffer size of 100 events

        let tx_clone = tx.clone();
        let hook = Box::new(move |action: Action, _db: &str, table: &str, row_id: i64| {
            match (action, table) {
                (Action::SQLITE_INSERT, "servers") => {
                    let _ = tx_clone.send(DatabaseChange::ServerAdded(row_id as u32));
                }
                (Action::SQLITE_DELETE, "servers") => {
                    let _ = tx_clone.send(DatabaseChange::ServerRemoved(row_id as u32));
                }
                (Action::SQLITE_UPDATE, "servers") => {
                    let _ = tx_clone.send(DatabaseChange::ServerUpdated(row_id as u32));
                }
                (Action::SQLITE_INSERT, "users")
                | (Action::SQLITE_UPDATE, "users")
                | (Action::SQLITE_DELETE, "users") => {
                    // For user operations, we'll just send the row_id since getting the username
                    // would require database access from within the hook
                    let _ = tx_clone.send(DatabaseChange::UserUpdated(row_id.to_string()));
                }
                _ => {} // Ignore other tables/actions
            }
        });

        // Set the update hook
        conn.update_hook(Some(hook));

        // Optional: Add commit hook for transaction monitoring
        let commit_hook = Box::new(|| {
            debug!("Database transaction committed");
            true // Return true to allow the commit
        });
        conn.commit_hook(Some(commit_hook));

        Ok((DatabaseWithHooks { conn, change_tx: tx }, rx))
    }

    fn get_username_by_rowid(conn: &Connection, row_id: i64) -> Result<String, RusqliteError> {
        conn.query_row("SELECT name FROM users WHERE rowid = ?", [row_id], |row| row.get(0))
    }

    // Example of how to use the hooks in existing methods
    /*
    pub fn add_server(&self, server: &ServerConfig) -> Result<u16, RusqliteError> {
        let mut stmt = self.conn.prepare(
            "INSERT INTO servers (
                ip_address, port, method, mode, key, active
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;

        stmt.execute(params![
            server.ip_address,
            server.port,
            server.method,
            server.mode,
            server.key,
            server.active,
        ])?;

        // The update hook will automatically fire and send the DatabaseChange event
        Ok(server.port)
    }

    // Example of how to use the hooks in your manager code:
    pub async fn handle_database_changes(mut rx: broadcast::Receiver<DatabaseChange>) {
        while let Ok(change) = rx.recv().await {
            match change {
                DatabaseChange::ServerAdded(port) => {
                    debug!("Server added on port {}", port);
                    // Handle server addition
                }
                DatabaseChange::ServerRemoved(port) => {
                    debug!("Server removed on port {}", port);
                    // Handle server removal
                }
                DatabaseChange::UserAdded(user_id) => {
                    debug!("User added with id {}", user_id);
                    // Handle user addition
                }
                _ => {} // Handle other changes
            }
        }
    }
     */
}

impl Database {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, RusqliteError> {
        let conn = Connection::open(path)?;
        // Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON", [])?;
        let mut db = Database { conn };
        db.init_schema()?;
        Ok(db)
    }

    pub fn close(self) {
        match self.conn.close() {
            Err(e) => debug!("Failed to close db: {:?}", e),
            Ok(_) => debug!("Closed db!!!!!!!"),
        }
    }

    pub fn init_schema(&mut self) -> Result<(), RusqliteError> {
        let tx = self.conn.transaction()?;

        // Config table - for storing general configuration
        tx.execute(
            "CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                config TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Servers table with additional fields
        tx.execute(
            "CREATE TABLE IF NOT EXISTS servers (
                ip_address TEXT NOT NULL,
                port INTEGER PRIMARY KEY,
                method TEXT NOT NULL,
                mode TEXT NOT NULL,
                key TEXT NOT NULL UNIQUE,
                active BOOLEAN NOT NULL DEFAULT TRUE,
                remarks TEXT,
                timeout_seconds INTEGER,
                tcp_weight REAL,
                udp_weight REAL,
                plugin TEXT,
                plugin_opts TEXT,
                plugin_args TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        // Users table with additional fields
        tx.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                key TEXT NOT NULL UNIQUE,
                server_port INTEGER NOT NULL,
                active BOOLEAN NOT NULL DEFAULT TRUE,
                remarks TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (server_port) REFERENCES servers(port)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            )",
            [],
        )?;

        // Create indices for better performance
        tx.execute("CREATE INDEX IF NOT EXISTS idx_servers_active ON servers(active)", [])?;
        tx.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_server_port ON users(server_port)",
            [],
        )?;
        tx.execute("CREATE INDEX IF NOT EXISTS idx_users_active ON users(active)", [])?;
        tx.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_servers_ip_port ON servers(ip_address, port)",
            [],
        )?;
        tx.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_name_server ON users(name, server_port)",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn save_config_to_tables(&mut self, config: &Config) -> Result<(), RusqliteError> {
        // Start a transaction to ensure all operations succeed or fail together
        let tx = self.conn.transaction()?;

        // First save any servers from the config
        for server_instance in &config.server {
            let server = &server_instance.config;

            // Get server address details
            let (ip_address, port) = match server.addr() {
                ServerAddr::SocketAddr(sock_addr) => (sock_addr.ip().to_string(), sock_addr.port()),
                ServerAddr::DomainName(domain, port) => (domain.to_string(), *port),
            };

            // Add the server
            tx.execute(
                "INSERT OR REPLACE INTO servers (
                    ip_address, port, method, mode, key, active
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    ip_address,
                    port,
                    server.method().to_string(),
                    server.mode().to_string(),
                    server.password().to_string(),
                    true, // Active by default
                ],
            )?;

            // Handle users if present
            if let Some(user_manager) = server.user_manager() {
                for user in user_manager.users_iter() {
                    tx.execute(
                        "INSERT OR REPLACE INTO users (
                            name, key, server_port, active
                        ) VALUES (?1, ?2, ?3, ?4)",
                        params![
                            user.name(),
                            user.encoded_key(), // This is the base64 encoded key
                            port,               // Link to the server
                            true,               // Active by default
                        ],
                    )?;
                }
            }
        }

        // Commit the transaction
        tx.commit()?;

        debug!("Successfully saved config to database tables");
        Ok(())
    }

    pub fn load_server_config(&self, port: u16) -> Result<Option<ServerConfig>, RusqliteError> {
        let mut stmt = self.conn.prepare(
            "SELECT
                ip_address, port, method, mode, key, active,
                remarks, timeout_seconds, tcp_weight, udp_weight,
                plugin, plugin_opts, plugin_args,
                created_at, updated_at
             FROM servers
             WHERE port = ?1",
        )?;

        let server = stmt
            .query_row(params![port], |row| {
                Ok(ServerConfig {
                    ip_address: row.get(0)?,
                    port: row.get(1)?,
                    method: row.get(2)?,
                    mode: row.get(3)?,
                    key: row.get(4)?,
                    active: row.get(5)?,
                    remarks: row.get(6)?,
                    timeout: row
                        .get::<_, Option<i64>>(7)?
                        .map(|secs| Duration::from_secs(secs as u64)),
                    tcp_weight: row.get(8)?,
                    udp_weight: row.get(9)?,
                    plugin: row.get(10)?,
                    plugin_opts: row.get(11)?,
                    plugin_args: row.get(12)?,
                    created_at: row.get(13)?,
                    updated_at: row.get(14)?,
                    users: Vec::new(), // We'll populate this next
                })
            })
            .optional()?;

        if let Some(mut server) = server {
            // Load users for this server
            server.users = self.get_users_by_server(port)?;
            Ok(Some(server))
        } else {
            Ok(None)
        }
    }
    pub fn load_config_from_tables(&self) -> Result<Vec<ServerInstanceConfig>, RusqliteError> {
        // Load servers with their users
        let servers = self.list_servers(true)?;
        let mut ret_servers = Vec::new();
        for server in servers {
            if server.active {
                // Convert to shadowsocks ServerConfig
                if let Ok(ss_config) = server.to_shadowsocks_config() {
                    ret_servers.push(ServerInstanceConfig::with_server_config(ss_config));
                }
            }
        }

        Ok(ret_servers)
    }

    pub fn generate_manager_config(
        &self,
        manager_port: u16,
        manager_sock_address: String,
    ) -> Result<ManagerConfig, RusqliteError> {
        let servers = self.list_servers_with_metadata()?;
        let mut config_servers = Vec::new();

        for mut server in servers {
            if server.active {
                let users = self.get_users_by_server(server.port)?;
                server.users = users.into_iter().collect();

                config_servers.push(server);
            }
        }
        let key = generate_manager_key().unwrap();

        Ok(ManagerConfig {
            manager_port,
            manager_sock_address,
            servers: config_servers,
            url_key: key,
        })
    }

    pub fn get_config(&self, manager_port: u16, sock_path: String) -> Result<String, RusqliteError> {
        // Get all active servers with their users
        let servers = self.list_servers(true)?; // Only get active servers
        let key = generate_manager_key().unwrap();
        // Create the manager config structure
        let config = ManagerConfig {
            manager_port,
            manager_sock_address: sock_path,
            servers,
            url_key: key,
        };

        // Serialize to JSON string
        let config_str = serde_json::to_string_pretty(&config)
            .map_err(|e| RusqliteError::InvalidParameterName(format!("Failed to serialize config: {}", e)))?;

        // pretty print the config!
        println!("\n=== Configuration ===");
        println!("{}", config_str);
        println!("===================\n");

        Ok(config_str)
    }

    // todo not sure I need this
    // Helper method to get server users in the format needed for the config
    #[allow(dead_code)]
    fn get_formatted_users(&self, server_port: u16) -> Result<Vec<UserConfig>, RusqliteError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, key, server_port, active, remarks, created_at, updated_at
             FROM users
             WHERE server_port = ?1 AND active = TRUE
             ORDER BY name",
        )?;

        let users = stmt
            .query_map(params![server_port], |row| {
                Ok(UserConfig {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    key: row.get(2)?,
                    server_port: row.get(3)?,
                    active: row.get(4)?,
                    remarks: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, RusqliteError>>()?;

        Ok(users)
    }

    pub fn get_server(&self, port: u16) -> Result<Option<ServerConfig>, RusqliteError> {
        let mut stmt = self.conn.prepare(
            "SELECT ip_address, port, method, mode, key, active, created_at,
             remarks, timeout_seconds, tcp_weight, udp_weight
             FROM servers
             WHERE port = ?1",
        )?;

        let server = stmt
            .query_row(params![port], |row| {
                Ok(ServerConfig {
                    ip_address: row.get(0)?,
                    port: row.get(1)?,
                    method: row.get(2)?,
                    mode: row.get(3)?,
                    key: row.get(4)?,
                    active: row.get(5)?,
                    created_at: row.get(6)?,
                    remarks: row.get(7)?,
                    timeout: row
                        .get::<_, Option<i64>>(8)?
                        .map(|secs| Duration::from_secs(secs as u64)),
                    tcp_weight: row.get(9)?,
                    udp_weight: row.get(10)?,
                    // todo populate the rest of these fields from the db, Im currently only using the
                    // ip_address, and method for generation a connection URL for users

                    plugin: None,
                    plugin_opts: None,
                    plugin_args: None,
                    updated_at: None,
                    users: Vec::new(),
                })
            })
            .optional()?;

        Ok(server)
    }

    // Add users to a server from an AddUser request
    pub fn add_or_update_users(&mut self, add_user: &AddUser) -> Result<(), RusqliteError> {
        // First collect all existing users, using key as the HashMap key
        let existing_users: HashMap<_, _> = self
            .get_users_by_server(add_user.server_port as u16)?
            .into_iter()
            .map(|user| (user.key.clone(), user))
            .collect();

        // Now start transaction and perform updates
        let tx = self.conn.transaction()?;

        for user in &add_user.users {
            match existing_users.get(&user.password) {
                Some(_) => {
                    // Update existing user - note we're matching on key now, not name
                    tx.execute(
                        "UPDATE users SET
                            name = ?1,
                            active = ?2,
                            updated_at = CURRENT_TIMESTAMP
                         WHERE key = ?3 AND server_port = ?4",
                        params![user.name, true, user.password, add_user.server_port,],
                    )?;
                }
                None => {
                    // Insert new user
                    tx.execute(
                        "INSERT INTO users (
                            name, key, server_port, active,
                            created_at, updated_at
                        ) VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                        params![user.name, user.password, add_user.server_port, true,],
                    )?;
                }
            }
        }

        // Update server's updated_at timestamp
        tx.execute(
            "UPDATE servers SET
                updated_at = CURRENT_TIMESTAMP
             WHERE port = ?1",
            params![add_user.server_port],
        )?;

        tx.commit()?;
        Ok(())
    }

    // Helper function to check if a user exists
    pub fn user_exists(&self, name: &str, server_port: u16) -> Result<bool, RusqliteError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM users WHERE name = ?1 AND server_port = ?2",
            params![name, server_port],
            |row| row.get(0),
        )?;

        Ok(count > 0)
    }

    // Helper function to get user by name and server port
    pub fn get_user(&self, name: &str, server_port: u16) -> Result<Option<UserConfig>, RusqliteError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, key, server_port, active, remarks, created_at, updated_at
             FROM users
             WHERE name = ?1 AND server_port = ?2",
        )?;

        stmt.query_row(params![name, server_port], |row| self.get_user_from_row(row))
            .optional()
    }
    pub fn rename_user(&self, id: i64, new_name: &str) -> Result<usize, RusqliteError> {
        let now = Utc::now().naive_utc();

        let ss = self.conn.execute(
            "UPDATE users
             SET name = ?1, updated_at = ?2
             WHERE id = ?3",
            params![new_name, now, id],
        )?;

        Ok(ss)
    }

    pub fn disable_user(&mut self, id: i64) -> Result<(), RusqliteError> {
        self.conn.execute(
            "UPDATE users
             SET active = FALSE, updated_at = ?1
             WHERE id = ?2",
            params![Utc::now().naive_utc(), id],
        )?;

        Ok(())
    }

    pub fn remove_user(&mut self, id: i64) -> Result<String, RusqliteError> {
        let ss = self.conn.execute(
            "DELETE FROM users WHERE id = ?2",
            params![Utc::now().naive_utc(), id],
        )?;

        Ok(format!("{} users deleted.", ss))
    }

    pub fn get_user_by_id(&self, id: i64) -> Result<Option<UserConfig>, RusqliteError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, key, server_port, active, remarks, created_at, updated_at
             FROM users
             WHERE id = ?1",
        )?;

        stmt.query_row(params![id], |row| self.get_user_from_row(row))
            .optional()
    }

    pub fn list_users_with_url(
        &self,
        active_only: bool,
        user_id: Option<i64>,
    ) -> Result<Vec<(UserConfig, (String, Option<String>))>, RusqliteError> {
        let where_clause = match user_id {
            Some(id) => {
                format!(
                    "WHERE users.id = {} {}",
                    id,
                    match active_only {
                        true => "AND users.active = TRUE",
                        false => "",
                    }
                )
            }
            None => format!(
                "{}",
                match active_only {
                    true => "WHERE users.active = TRUE",
                    false => "",
                }
            ),
        };
        let query = format!(
            "SELECT users.id, users.name, users.key, users.server_port,
                users.active, users.remarks, users.created_at, users.updated_at,
                servers.method, servers.ip_address
             FROM users
             INNER JOIN servers ON servers.port = users.server_port
             {}
             ORDER BY users.id",
            where_clause
        );

        let mut stmt = self.conn.prepare(&query)?;

        let users = stmt
            .query_map([], |row| {
                let url = match generate_ssurl(
                    &row.get::<usize, String>(9)?,
                    row.get(3)?,
                    &row.get::<usize, String>(8)?,
                    &row.get::<usize, String>(2)?,
                    Some(&row.get::<usize, String>(1)?),
                ) {
                    Ok(url) => Some(url),
                    Err(_) => Some("Error generating URL".to_string()),
                };
                Ok((self.get_user_from_row(row)?, (row.get::<usize, String>(8)?, url)))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(users)
    }
    pub fn list_users(&self, active_only: bool) -> Result<Vec<UserConfig>, RusqliteError> {
        let query = if active_only {
            "SELECT id, name, key, server_port, active, remarks, created_at, updated_at
             FROM users
             WHERE active = TRUE
             ORDER BY id"
        } else {
            "SELECT id, name, key, server_port, active, remarks, created_at, updated_at
             FROM users
             ORDER BY id"
        };

        let mut stmt = self.conn.prepare(query)?;

        let users = stmt
            .query_map([], |row| self.get_user_from_row(row))?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(users)
    }
    fn get_user_from_row(&self, row: &Row) -> Result<UserConfig, RusqliteError> {
        Ok(UserConfig {
            id: Some(row.get(0)?),
            name: row.get(1)?,
            key: row.get(2)?,
            server_port: row.get(3)?,
            active: row.get(4)?,
            remarks: row.get(5)?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
        })
    }

    // Function to update an existing user
    pub fn update_user(&self, user: &UserConfig) -> Result<(), RusqliteError> {
        self.conn.execute(
            "UPDATE users SET
                key = ?1,
                active = ?2,
                remarks = ?3,
                updated_at = CURRENT_TIMESTAMP
             WHERE name = ?4 AND server_port = ?5",
            params![user.key, user.active, user.remarks, user.name, user.server_port,],
        )?;

        Ok(())
    }

    pub fn list_servers(&self, active_only: bool) -> Result<Vec<ServerConfig>, RusqliteError> {
        let base_query = "SELECT
                ip_address, port, method, mode, key, active,
                remarks, timeout_seconds, tcp_weight, udp_weight,
                plugin, plugin_opts, plugin_args,
                created_at, updated_at
             FROM servers";

        let query = if active_only {
            format!("{} WHERE active = TRUE ORDER BY port", base_query)
        } else {
            format!("{} ORDER BY port", base_query)
        };

        let mut stmt = self.conn.prepare(&query)?;

        let servers = stmt
            .query_map([], |row| {
                Ok(ServerConfig {
                    ip_address: row.get(0)?,
                    port: row.get(1)?,
                    method: row.get(2)?,
                    mode: row.get(3)?,
                    key: row.get(4)?,
                    active: row.get(5)?,
                    remarks: row.get(6)?,
                    timeout: row
                        .get::<_, Option<i64>>(7)?
                        .map(|secs| Duration::from_secs(secs as u64)),
                    tcp_weight: row.get(8)?,
                    udp_weight: row.get(9)?,
                    plugin: row.get(10)?,
                    plugin_opts: row.get(11)?,
                    plugin_args: row.get(12)?,
                    created_at: row.get(13)?,
                    updated_at: row.get(14)?,
                    users: Vec::new(), // Users will be populated later if needed
                })
            })?
            .collect::<Result<Vec<_>, RusqliteError>>()?;

        let mut servers_with_users = Vec::with_capacity(servers.len());
        for mut server in servers {
            // Load users for each server
            server.users = self.get_users_by_server(server.port)?;
            servers_with_users.push(server);
        }

        Ok(servers_with_users)
    }

    // Companion method that includes extra metadata without loading users
    pub fn list_servers_with_metadata(&self) -> Result<Vec<ServerConfig>, RusqliteError> {
        let query = "SELECT
                s.ip_address, s.port, s.method, s.mode, s.key, s.active,
                s.remarks, s.timeout_seconds, s.tcp_weight, s.udp_weight,
                s.plugin, s.plugin_opts, s.plugin_args,
                s.created_at, s.updated_at,
                COUNT(u.id) as user_count
             FROM servers s
             LEFT JOIN users u ON s.port = u.server_port
             GROUP BY s.port
             ORDER BY s.port";

        let mut stmt = self.conn.prepare(query)?;

        let servers = stmt
            .query_map([], |row| {
                Ok(ServerConfig {
                    ip_address: row.get(0)?,
                    port: row.get(1)?,
                    method: row.get(2)?,
                    mode: row.get(3)?,
                    key: row.get(4)?,
                    active: row.get(5)?,
                    remarks: row.get(6)?,
                    timeout: row
                        .get::<_, Option<i64>>(7)?
                        .map(|secs| Duration::from_secs(secs as u64)),
                    tcp_weight: row.get(8)?,
                    udp_weight: row.get(9)?,
                    plugin: row.get(10)?,
                    plugin_opts: row.get(11)?,
                    plugin_args: row.get(12)?,
                    created_at: row.get(13)?,
                    updated_at: row.get(14)?,
                    users: Vec::new(), // Left empty for metadata-only queries
                })
            })?
            .collect::<Result<Vec<_>, RusqliteError>>()?;

        Ok(servers)
    }

    pub fn add_user(
        &mut self,
        name: String,
        key: String,
        server_port: u16,
        active: bool,
    ) -> Result<(UserConfig, Option<String>), Error> {
        let url: Option<String>;
        match self.get_server(server_port) {
            Ok(srvs) => match srvs {
                Some(srv) => {
                    let ipaddr = &srv.ip_address;
                    let method = &srv.method;
                    url = match generate_ssurl(&ipaddr, server_port, method, &key, Some(&name)) {
                        Ok(url) => Some(url),
                        Err(_) => None,
                    };
                }
                None => {
                    return Err(Error::InvalidParameterName(
                        "Server port does not exist or is not active".into(),
                    ));
                }
            },
            Err(err) => {
                error!("failed to get server port: {}", err);
                return Err(Error::InvalidParameterName("Failed to get server".into()));
            }
        }

        let tx = self.conn.transaction()?;

        // Verify name and port combination is unique
        let name_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE name = ? AND server_port = ?)",
            params![name, server_port],
            |row| row.get(0),
        )?;

        if name_exists {
            return Err(Error::InvalidParameterName(
                "User name already exists for this server".into(),
            ));
        }

        // Get current timestamp
        let now = Utc::now().naive_utc();

        // Insert the new user
        tx.execute(
            "INSERT INTO users (
                name,
                key,
                server_port,
                active,
                created_at,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![name, key, server_port, active, now, now,],
        )?;

        // Get the inserted user's ID
        let id = tx.last_insert_rowid();

        // Commit the transaction
        tx.commit()?;

        // Return the created user config
        Ok((
            UserConfig {
                id: Some(id),
                name,
                key,
                server_port,
                active,
                remarks: None,
                created_at: Some(now),
                updated_at: Some(now),
            },
            url,
        ))
    }

    pub fn get_users_by_server(&self, server_port: u16) -> Result<Vec<UserConfig>, RusqliteError> {
        let mut stmt = self.conn.prepare(
            "SELECT
                id, name, key, server_port, active, remarks,
                created_at, updated_at
             FROM users
             WHERE server_port = ?1
             ORDER BY name",
        )?;

        let users = stmt
            .query_map(params![server_port], |row| {
                Ok(UserConfig {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    key: row.get(2)?,
                    server_port: row.get(3)?,
                    active: row.get(4)?,
                    remarks: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, RusqliteError>>()?;

        Ok(users)
    }

    pub fn build_ssurl_params_from_user_id(
        &self,
        user_id: i64,
        default_server_address: &str,
    ) -> Result<SsUrlParams, RusqliteError> {
        // First get the user details
        let mut stmt = self.conn.prepare(
            "SELECT name, key, server_port
         FROM users
         WHERE id = ? AND active = TRUE",
        )?;

        let user = stmt.query_row([user_id], |row| {
            Ok((
                row.get::<_, String>(0)?, // name
                row.get::<_, String>(1)?, // key/password
                row.get::<_, u32>(2)?,    // server_port
            ))
        })?;

        let (user_name, password, server_port) = user;

        // Then get the server details for this port
        let mut stmt = self.conn.prepare(
            "SELECT method, mode
         FROM servers
         WHERE port = ? AND active = TRUE",
        )?;

        let server = stmt.query_row([server_port], |row| {
            Ok((
                row.get::<_, String>(0)?, // method
                row.get::<_, String>(1)?, // mode
            ))
        })?;

        let (method, _mode) = server;

        Ok(SsUrlParams {
            server_address: default_server_address.to_string(),
            server_port: server_port as u16,
            method,
            password,
            name: Some(user_name),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_manager_key() {
        // Test key generation and length
        let key = generate_manager_key().unwrap();

        // Decode the key
        let decoded = URL_SAFE.decode(key).unwrap();

        // Check that the original key was 16 bytes
        assert_eq!(decoded.len(), 16);

        // Generate multiple keys and ensure they're different
        let key1 = generate_manager_key().unwrap();
        let key2 = generate_manager_key().unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_key_format() {
        let key = generate_manager_key().unwrap();

        // Check that the key only contains valid URL-safe base64 characters
        assert!(key.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_'
        }));
    }
}
