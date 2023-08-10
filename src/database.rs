use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::sync::Arc;

use anyhow::Error;
use log::{error, info};
use sqlx::{Pool, Sqlite, SqlitePool};

use crate::config::DB_PATH;

pub async fn init_db_pool() -> Result<Arc<Pool<Sqlite>>, Error> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(DB_PATH)
    {
        Ok(_) => info!("Database file created successfully."),
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => info!("Database file already exists."),
        Err(e) => return Err(Error::from(e)),
    }

    let pool = SqlitePool::connect(&format!("sqlite:{}", DB_PATH)).await?;

    // Enable WAL mode
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&pool)
        .await?;

    Ok(Arc::new(pool))
}

/// Creates the 'url_status' table if it doesn't exist.
pub async fn create_table(pool: &Pool<Sqlite>) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS url_status (
        id INTEGER PRIMARY KEY,
        domain TEXT NOT NULL,
        final_domain TEXT NOT NULL,
        status INTEGER NOT NULL,
        status_description TEXT NOT NULL,
        response_time NUMERIC(10, 2),
        title TEXT NOT NULL,
        timestamp INTEGER NOT NULL
    )",
    )
        .execute(pool)
        .await?;

    Ok(())
}

/// Inserts a new URL status into the database.
pub async fn update_database(
    initial_domain: &str,
    final_domain: &str,
    status: reqwest::StatusCode,
    status_desc: &str,
    elapsed: f64,
    title: &str,
    timestamp: i64,
    pool: &SqlitePool,
) -> Result<(), Error> {
    match sqlx::query(
        "INSERT INTO url_status (domain, final_domain, status, status_description, response_time, title, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
        .bind(&initial_domain)
        .bind(&final_domain)
        .bind(status.as_u16())
        .bind(status_desc)
        .bind(elapsed)
        .bind(&title)
        .bind(timestamp)
        .execute(pool)
        .await {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("Error when accessing the database: {}", e);
            Err(e.into())
        }
    }
}