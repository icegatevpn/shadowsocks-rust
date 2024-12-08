use std::collections::HashMap;
use crate::config::{Config, ConfigType, ServerInstanceConfig};
use chrono::{Date, DateTime, NaiveDateTime, TimeZone, Utc};
use log::debug;
use rusqlite::{params, types::{FromSql, FromSqlResult, ToSql, ToSqlOutput, ValueRef}, Connection, Error as RusqliteError, OptionalExtension,
               Statement};
use serde::{Deserialize, Serialize};
use shadowsocks::config::{Mode, ServerConfig as SSServerConfig, ServerUser, ServerUserManager, ServerWeight};
use shadowsocks::crypto::CipherKind;
use shadowsocks::plugin::PluginConfig;
use shadowsocks::ServerAddr;
use std::fmt::Display;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, SystemTime};
use shadowsocks::manager::protocol::AddUser;

// Custom serializer/deserializer for DateTime<Utc>
mod datetime_format {
    use super::*;
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(date: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match date {
            Some(dt) => serializer.serialize_i64(dt.timestamp()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<i64>::deserialize(deserializer).map(|opt_ts| {
            opt_ts.map(|ts| Utc.timestamp_opt(ts, 0).unwrap())
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(rename = "server")]
    pub ip_address: String,
    #[serde(rename = "server_port")]
    pub port: u32,
    pub method: String,
    pub mode: String,
    #[serde(rename = "password")]
    pub key: String,

    // Database only fields
    #[serde(skip_serializing)]
    pub active: bool,

    // #[serde(with = "datetime_format")]
    pub created_at: Option<NaiveDateTime>,
    pub remarks: Option<String>,
    pub timeout: Option<Duration>,
    pub tcp_weight: Option<f32>,
    pub udp_weight: Option<f32>,
    pub plugin: Option<String>,
    pub plugin_opts: Option<String>,
    pub plugin_args: Option<String>,
    pub updated_at: Option<NaiveDateTime>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<UserConfig>,
}
impl ServerConfig {
    pub fn new(addr: ServerAddr, password: String, method: CipherKind) -> Result<Self, RusqliteError> {
        let (ip_address, port) = match addr {
            ServerAddr::SocketAddr(sock_addr) => (sock_addr.ip().to_string(), sock_addr.port() as u32),
            ServerAddr::DomainName(domain, port) => (domain, port as u32),
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
    // pub fn created_at(&self) -> Option<DateTime<Utc>> {
    //     self.created_at
    // }
    pub fn to_shadowsocks_config(&self) -> Result<SSServerConfig, RusqliteError> {
        let addr = if let Ok(ip) = self.ip_address.parse() {
            ServerAddr::SocketAddr(SocketAddr::new(ip, self.port as u16))
        } else {
            ServerAddr::DomainName(self.ip_address.clone(), self.port as u16)
        };

        let method = self.method.parse::<CipherKind>()
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
                plugin_args: self.plugin_args.as_ref()
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
                        Ok(ss_user) => { let _ = user_manager.add_user(ss_user); },
                        Err(e) => {
                            return Err(RusqliteError::InvalidParameterName(
                                format!("Failed to create user {}: {}", user.name, e)
                            ));
                        }
                    }
                }
            }
            ss_config.set_user_manager(user_manager);
        }

        Ok(ss_config)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManagerConfig {
    // manager_tcp_address: Option<String>,
    manager_port: u32,
    manager_sock_address: String,
    servers: Vec<ServerConfig>
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserConfig {
    #[serde(skip_serializing)]
    pub id: Option<i64>,
    pub name: String,
    #[serde(rename = "password")]
    pub key: String,
    #[serde(skip_serializing)]
    pub server_port: u32,
    #[serde(skip_serializing)]
    pub active: bool,
    pub remarks: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Debug)]
pub struct Database {
    pub conn: Connection,
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
        tx.execute(
            "CREATE INDEX IF NOT EXISTS idx_servers_active ON servers(active)",
            [],
        )?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_server_port ON users(server_port)",
            [],
        )?;

        tx.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_active ON users(active)",
            [],
        )?;

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
                    port as u32,
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
                            user.encoded_key(),  // This is the base64 encoded key
                            port as u32,         // Link to the server
                            true,                // Active by default
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

    pub fn load_server_config(&self, port: u32) -> Result<Option<ServerConfig>, RusqliteError> {
        let mut stmt = self.conn.prepare(
            "SELECT
                ip_address, port, method, mode, key, active,
                remarks, timeout_seconds, tcp_weight, udp_weight,
                plugin, plugin_opts, plugin_args,
                created_at, updated_at
             FROM servers
             WHERE port = ?1"
        )?;

        let server = stmt.query_row(params![port], |row| {
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
                users: Vec::new(), // We'll populate this next
            })
        }).optional()?;

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

    pub fn generate_manager_config(&self,
                                   manager_port: u32,
                                   manager_sock_address: String
    ) -> Result<ManagerConfig, RusqliteError> {
        let servers = self.list_servers_with_metadata()?;
        let mut config_servers = Vec::new();

        for mut server in servers {
            if server.active {
                let users = self.get_users_by_server(server.port)?;
                server.users = users.into_iter()
                    // .filter(|user| user.active)
                    .collect();

                config_servers.push(server);
            }
        }

        Ok(ManagerConfig {
            manager_port,
            manager_sock_address,
            servers: config_servers,
        })
    }

    pub fn get_config(&self, manager_port: u32, sock_path: String) -> Result<String, RusqliteError> {
        // Get all active servers with their users
        let servers = self.list_servers(true)?; // Only get active servers

        // Create the manager config structure
        let config = ManagerConfig {
            manager_port,
            manager_sock_address: sock_path,
            servers,
        };

        // Serialize to JSON string
        let config_str = serde_json::to_string_pretty(&config)
            .map_err(|e| RusqliteError::InvalidParameterName(format!("Failed to serialize config: {}", e)))?;

        Ok(config_str)
    }

    // todo not sure I need this
    // Helper method to get server users in the format needed for the config
    fn get_formatted_users(&self, server_port: u32) -> Result<Vec<UserConfig>, RusqliteError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, key, server_port, active, remarks, created_at, updated_at
             FROM users
             WHERE server_port = ?1 AND active = TRUE
             ORDER BY name"
        )?;

        let users = stmt.query_map(params![server_port], |row| {
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


    // pub fn add_server(&self, server: &ServerConfig) -> Result<u32, RusqliteError> {
    //     let mut stmt = self.conn.prepare(
    //         "INSERT INTO servers (
    //         ip_address, port, method, mode, key, active, created_at)
    //         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    //     )?;
    //     let created_at = Utc::now();
    //
    //     stmt.execute(params![
    //         server.ip_address,
    //         server.port,
    //         server.method,
    //         server.mode,
    //         server.key,
    //         server.active,
    //         created_at.timestamp(),
    //     ])?;
    //
    //     Ok(server.port)
    // }

    // pub fn get_server(&self, port: u32) -> Result<Option<ServerConfig>, RusqliteError> {
    //     let mut stmt = self.conn.prepare(
    //         "SELECT ip_address, port, method, mode, key, active, created_at
    //          FROM servers
    //          WHERE port = ?1",
    //     )?;
    //
    //     let server = stmt
    //         .query_row(params![port], |row| {
    //             let timestamp: i64 = row.get(6)?;
    //             Ok(ServerConfig {
    //                 ip_address: row.get(0)?,
    //                 port: row.get(1)?,
    //                 method: row.get(2)?,
    //                 mode: row.get(3)?,
    //                 key: row.get(4)?,
    //                 active: row.get(5)?,
    //                 // created_at: row.get(6)?,
    //                 created_at: Some(Utc.timestamp_opt(timestamp, 0).unwrap()),
    //                 users: Vec::new()
    //             })
    //         })
    //         .optional()?;
    //
    //     Ok(server)
    // }

    // pub fn update_server(&self, server: &ServerConfig) -> Result<(), RusqliteError> {
    //     let now = chrono::Utc::now().naive_utc();
    //
    //     let mut stmt = self.conn.prepare(
    //         "UPDATE servers SET
    //             ip_address = ?1,
    //             method = ?2,
    //             mode = ?3,
    //             key = ?4,
    //             active = ?5,
    //          WHERE port = ?6",
    //     )?;
    //
    //     stmt.execute(params![
    //         server.ip_address,
    //         server.method,
    //         server.mode,
    //         server.key,
    //         server.active,
    //         server.port,
    //     ])?;
    //
    //     Ok(())
    // }
    // Get all users for a specific server port

    // Add users to a server from an AddUser request
    pub fn add_or_update_users(&mut self, add_user: &AddUser) -> Result<(), RusqliteError> {
        // First collect all existing users, using key as the HashMap key
        let existing_users: HashMap<_, _> = self.get_users_by_server(add_user.server_port as u32)?
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
                        params![
                            user.name,
                            true,
                            user.password,
                            add_user.server_port as u32,
                        ],
                    )?;
                }
                None => {
                    // Insert new user
                    tx.execute(
                        "INSERT INTO users (
                            name, key, server_port, active,
                            created_at, updated_at
                        ) VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                        params![
                            user.name,
                            user.password,
                            add_user.server_port as u32,
                            true,
                        ],
                    )?;
                }
            }
        }

        // Update server's updated_at timestamp
        tx.execute(
            "UPDATE servers SET
                updated_at = CURRENT_TIMESTAMP
             WHERE port = ?1",
            params![add_user.server_port as u32],
        )?;

        tx.commit()?;
        Ok(())
    }

    // Helper function to check if a user exists
    pub fn user_exists(&self, name: &str, server_port: u32) -> Result<bool, RusqliteError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM users WHERE name = ?1 AND server_port = ?2",
            params![name, server_port],
            |row| row.get(0),
        )?;

        Ok(count > 0)
    }

    // Helper function to get user by name and server port
    pub fn get_user(&self, name: &str, server_port: u32) -> Result<Option<UserConfig>, RusqliteError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, key, server_port, active, remarks, created_at, updated_at
             FROM users
             WHERE name = ?1 AND server_port = ?2"
        )?;

        stmt.query_row(
            params![name, server_port],
            |row| Ok(UserConfig {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                key: row.get(2)?,
                server_port: row.get(3)?,
                active: row.get(4)?,
                remarks: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        ).optional()
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
            params![
                user.key,
                user.active,
                user.remarks,
                user.name,
                user.server_port,
            ],
        )?;

        Ok(())
    }

    pub fn list_servers(&self, active_only: bool) -> Result<Vec<ServerConfig>, RusqliteError> {
        let base_query =
            "SELECT
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
                    timeout: row.get::<_, Option<i64>>(7)?
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
        let query =
            "SELECT
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
                    timeout: row.get::<_, Option<i64>>(7)?
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

    pub fn get_users_by_server(&self, server_port: u32) -> Result<Vec<UserConfig>, RusqliteError> {
        let mut stmt = self.conn.prepare(
            "SELECT
                id, name, key, server_port, active, remarks,
                created_at, updated_at
             FROM users
             WHERE server_port = ?1
             ORDER BY name"
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

}
