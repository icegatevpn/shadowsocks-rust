use rusqlite::Error as RusqliteError;
use rusqlite::{params, Connection, Error, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::path::Path;
use log::debug;
use crate::config::Config;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    id: Option<i64>,
    username: String,
    email: String,
    active: bool,
}

#[derive(Debug)]
pub struct Database {
    pub conn: Connection,
}

/*
   An example Database of Users with some example functionality.
*/
impl Database {
    pub fn close(self) {
        match self.conn.close() {
            Err(e) => debug!("Failed to close db: {:?}", e),
            Ok(_) => debug!("Closed db!!!!!!!"),
        }
    }

    fn init_schema(&self) -> Result<(), Error> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                config TEXT UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        Ok(())
    }

    pub fn save_service_config(&self, config: &Config) -> Result<(i64), Error> {
        debug!("<<<<<< save config: {}", config.to_string());
        let mut stmt = self.conn.prepare(
            "INSERT INTO config (name, config)
             VALUES (?1, ?2)",
        )?;

        stmt.execute(params!["Main", config.to_string()])?;

        Ok(self.conn.last_insert_rowid())
    }
    // Get user by ID
    pub fn get_config(&self, id: i64) -> Result<Option<String>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT config
             FROM config
             WHERE id = ?1",
        )?;

        let config = stmt
            .query_row(params![id], |row| {
                Ok(row.get(0)?)
            })
            .optional()?;

        Ok(config)
    }

    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let conn = Connection::open(path)?;

        // Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON", [])?;

        let db = Database { conn };
        db.init_schema()?;

        Ok(db)
    }



    pub fn add_user(&self, username: String, email: String, active: bool) -> Result<User, Error> {
        let mut stmt = self.conn.prepare(
            "INSERT INTO users (username, email, active)
             VALUES (?1, ?2, ?3)",
        )?;

        stmt.execute(params![username, email, active,])?;

        Ok(User {
            id: Some(self.conn.last_insert_rowid()),
            username,
            email,
            active,
        })
    }

    // Get user by ID
    pub fn get_user(&self, id: i64) -> Result<Option<User>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, username, email, active
             FROM users
             WHERE id = ?1",
        )?;

        let user = stmt
            .query_row(params![id], |row| {
                Ok(User {
                    id: Some(row.get(0)?),
                    username: row.get(1)?,
                    email: row.get(2)?,
                    active: row.get(3)?,
                })
            })
            .optional()?;

        Ok(user)
    }

    // Update user
    pub fn update_user(&self, user: User) -> Result<usize, Error> {
        let id = user
                .id
                // .ok_or_else(|| <&str as Into<Error>>::into("User ID is required for update").into())?;
            .ok_or_else(|| RusqliteError::InvalidParameterName("User ID is required for update".into()))?;

        let mut stmt = self.conn.prepare(
            "UPDATE users
             SET username = ?1, email = ?2, active = ?3
             WHERE id = ?4",
        )?;

        let rows_affected = stmt.execute(params![&user.username, &user.email, &user.active, id,])?;

        Ok(rows_affected)
    }

    pub fn delete_user(&self, id: i64) -> Result<usize, Error> {
        let rows_affected = self.conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;

        Ok(rows_affected)
    }

    // List all users with optional filters
    pub fn list_users(&self, active_only: bool) -> Result<Vec<User>, Error> {
        let mut stmt = if active_only {
            self.conn.prepare(
                "SELECT id, username, email, active
                 FROM users
                 WHERE active = TRUE
                 ORDER BY username",
            )?
        } else {
            self.conn.prepare(
                "SELECT id, username, email, active
                 FROM users
                 ORDER BY username",
            )?
        };

        let users = stmt
            .query_map([], |row| {
                Ok(User {
                    id: Some(row.get(0)?),
                    username: row.get(1)?,
                    email: row.get(2)?,
                    active: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(users)
    }
}
