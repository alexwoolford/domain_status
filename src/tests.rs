use std::sync::Arc;

use reqwest::Client;
use sqlx::{Pool, Sqlite};

use crate::{ErrorStats, init_extractor, process_url};

use super::*;

async fn count_records(pool: &sqlx::Pool<Sqlite>) -> i64 {
    let row: (i64, ) = sqlx::query_as("SELECT COUNT(*) FROM url_status")
        .fetch_one(pool)
        .await
        .expect("Failed to count records");

    row.0
}

#[tokio::test]
async fn test_process_url() -> Result<(), Box<dyn std::error::Error>> {
    let client = Arc::new(Client::new());
    let pool = Pool::<Sqlite>::connect("sqlite::memory:").await.unwrap();

    create_table(&pool).await?;

    let extractor = init_extractor();
    let error_stats = ErrorStats {
        connection_refused: Arc::new(AtomicUsize::new(0)),
        dns_error: Arc::new(AtomicUsize::new(0)),
        title_extract_error: Arc::new(AtomicUsize::new(0)),
        other_errors: Arc::new(AtomicUsize::new(0)),
    };

    // Url for testing
    let url = "https://example.com".to_string();

    let count_before = count_records(&pool).await;
    process_url(url, client.clone(), Arc::new(pool.clone()), extractor.clone(), error_stats.clone()).await;
    let count_after = count_records(&pool).await;

    let expected_increase = 1;
    assert_eq!(count_after, count_before + expected_increase, "Record count did not increase by the expected amount");

    Ok(())
}
