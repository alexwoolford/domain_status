use std::fs::OpenOptions;
use std::sync::Arc;
use log::{error, info};
use sqlx::{Pool, Sqlite, SqlitePool};
use std::io::ErrorKind;
use anyhow::Error;

pub async fn init_db_pool() -> Result<Arc<Pool<Sqlite>>, sqlx::Error> {
    let db_path = "./url_checker.db";

    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(db_path)
    {
        Ok(_) => info!("Database file created successfully."),
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
            info!("Database file already exists.")
        }
        Err(e) => panic!("Couldn't create database file: {:?}", e),
    }

    let pool = SqlitePool::connect(&*format!("sqlite:{}", db_path)).await?;

    // Enable WAL mode
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&pool)
        .await?;

    Ok(Arc::new(pool))
}

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