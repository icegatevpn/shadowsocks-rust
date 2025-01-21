use std::fmt::Display;
use std::path::Path;
// use rusqlite::{params, Connection, Error, OptionalExtension};
use rusqlite::Error as RusqliteError;
use serde::{Deserialize, Serialize};
use tokio_rusqlite::{params, Connection, Error, OptionalExtension, Result};
#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: Option<i64>,
    username: String,
    email: String,
    active: bool,
}

#[derive(Debug)]
pub(crate) struct TokioDatabase {
    pub conn: Connection,
}

/*
   An example Tokio Database of Users with some example functionality.
*/
impl TokioDatabase {
    async fn init_schema(&self) -> Result<()> {
        // self.conn.execute(
        self.conn
            .call(|conn| {
                conn.execute(
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
            })
            .await
            .expect("TODO: panic message");
        Ok(())
    }

    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path).await?;

        // Enable foreign keys
        conn.call(|inner_conn| {
            inner_conn.execute("PRAGMA foreign_keys = ON", [])?;
            Ok(())
        }).await?;

        let db = TokioDatabase { conn };
        db.init_schema().await?;

        Ok(db)
    }

    pub async fn create_user(&self, user: User) -> Result<i64> {
        let user_id = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "INSERT INTO users (username, email, active)
             VALUES (?1, ?2, ?3)",
                )?;

                stmt.execute(params![user.username, user.email, user.active,])?;

                Ok(conn.last_insert_rowid())
            })
            .await
            .expect("failed to create user"); //.clone();
        Ok(user_id)
    }

    // Get user by ID
    pub async fn get_user(&self, id: i64) -> Result<Option<User>> {
        let user = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
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
            })
            .await
            .expect("failed to get user");
        Ok(user)
    }

    // Update user
    pub async fn update_user(&self, user: User) -> Result<usize> {
        let ret_val = self
            .conn
            .call(move |conn| {
                let id = user
                .id
                // .ok_or_else(|| <&str as Into<Error>>::into("User ID is required for update").into())?;
            .ok_or_else(|| RusqliteError::InvalidParameterName("User ID is required for update".into()))?;

                let mut stmt = conn.prepare(
                    "UPDATE users
             SET username = ?1, email = ?2, active = ?3
             WHERE id = ?4",
                )?;

                let rows_affected = stmt.execute(params![&user.username, &user.email, &user.active, id,])?;

                Ok(rows_affected)
            })
            .await
            .expect("failed to update user");
        Ok(ret_val)
    }
    //
    // pub fn delete_user(&self, id: i64) -> Result<usize, Error> {
    //     let rows_affected = self.conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;
    //
    //     Ok(rows_affected)
    // }
    //
    // // List all users with optional filters
    // pub fn list_users(&self, active_only: bool) -> Result<Vec<User>, Error> {
    //     let mut stmt = if active_only {
    //         self.conn.prepare(
    //             "SELECT id, username, email, active
    //              FROM users
    //              WHERE active = TRUE
    //              ORDER BY username",
    //         )?
    //     } else {
    //         self.conn.prepare(
    //             "SELECT id, username, email, active
    //              FROM users
    //              ORDER BY username",
    //         )?
    //     };
    //
    //     let users = stmt
    //         .query_map([], |row| {
    //             Ok(User {
    //                 id: Some(row.get(0)?),
    //                 username: row.get(1)?,
    //                 email: row.get(2)?,
    //                 active: row.get(3)?,
    //             })
    //         })?
    //         .collect::<Result<Vec<_>, Error>>()?;
    //
    //     Ok(users)
    // }
}
