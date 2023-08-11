use std::sync::Arc;

use anyhow::Error;
use anyhow::Result;
use log::error;
use scraper::{Html, Selector};
use sqlx::SqlitePool;
use structopt::lazy_static::lazy_static;
use tldextract::TldExtractor;

use crate::database::update_database;
use crate::error_handling::{ErrorStats, ErrorType, get_retry_strategy, update_error_stats};

lazy_static! {
    static ref TITLE_SELECTOR: Selector = Selector::parse("title").unwrap();
}

fn extract_domain(extractor: &TldExtractor, url: &str) -> Result<String, anyhow::Error> {
    extractor.extract(url)
        .map_err(|e| anyhow::anyhow!("Extractor error: {}", e))
        .and_then(|extract| {
            if let Some(main_domain) = extract.domain {
                Ok(format!(
                    "{}.{}",
                    main_domain.to_lowercase(),
                    extract.suffix.unwrap_or_default()
                ))
            } else {
                // Domain not present in the URL, return an error
                Err(anyhow::anyhow!("Failed to extract domain from {}", url))
            }
        })
}

async fn handle_response(
    response: reqwest::Response,
    url: &str,
    pool: &SqlitePool,
    extractor: &TldExtractor,
    error_stats: &ErrorStats,
    elapsed: f64,
) -> Result<(), Error> {
    let final_url = response.url().to_string();
    let status = response.status();
    let status_desc = status.canonical_reason().unwrap_or_else(|| "Unknown Status Code");

    let title = response.text().await.map(|body| extract_title(&body, error_stats)).unwrap_or_default();

    let initial_domain = extract_domain(&extractor, url)?;
    let final_domain = extract_domain(&extractor, &final_url)?;

    let timestamp = chrono::Utc::now().timestamp_millis();

    update_database(&initial_domain, &final_domain, status, status_desc, elapsed, &title, timestamp, pool).await
}

async fn handle_http_request(
    client: &reqwest::Client,
    url: &str,
    pool: &SqlitePool,
    extractor: &TldExtractor,
    error_stats: &ErrorStats,
    start_time: std::time::Instant,
) -> Result<(), Error> {
    let res = client.get(url).send().await;
    let elapsed = start_time.elapsed().as_secs_f64();

    match res {
        Ok(response) => handle_response(response, url, pool, extractor, error_stats, elapsed).await,
        Err(e) => {
            update_error_stats(error_stats, &e);
            Err(e.into())
        }
    }
}

fn extract_title(html: &str, error_stats: &ErrorStats) -> String {
    let parsed_html = Html::parse_document(html);

    // Use the pre-created selector.
    match parsed_html.select(&TITLE_SELECTOR).next() {
        Some(element) => element.inner_html().trim().to_string(),
        None => {
            error_stats.increment(ErrorType::TitleExtractError);
            String::from("")
        }
    }
}

pub async fn process_url(
    url: String,
    client: Arc<reqwest::Client>,
    pool: Arc<SqlitePool>,
    extractor: Arc<TldExtractor>,
    error_stats: Arc<ErrorStats>,
) {
    let retry_strategy = get_retry_strategy();
    let start_time = std::time::Instant::now();

    let future = tokio_retry::Retry::spawn(retry_strategy, || {
        let client = client.clone();
        let url = url.clone();
        let pool = pool.clone();
        let extractor = extractor.clone();
        let error_stats = error_stats.clone();

        tokio::task::spawn(async move {
            handle_http_request(&*client, &url, &*pool, &*extractor, &error_stats, start_time).await
        })
    });

    match future.await {
        Ok(_) => {}
        Err(e) => error!("Error after retries: {}", e),
    }
}
