use anyhow::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use log::error;
use scraper::{Html, Selector};
use sqlx::SqlitePool;
use tldextract::TldExtractor;
use crate::config::ErrorStats;
use crate::database::update_database;
use crate::error_handling::{get_retry_strategy, update_error_stats, update_title_extract_error};


fn extract_domain(extractor: &TldExtractor, url: &str) -> String {
    return match extractor.extract(url) {
        Ok(extract) => {
            if let Some(main_domain) = extract.domain {
                format!(
                    "{}.{}",
                    main_domain.to_lowercase(),
                    extract.suffix.unwrap_or_default()
                )
            } else {
                // Domain not present in the URL, return an empty string
                "".to_string()
            }
        }
        Err(err) => {
            error!("Error when extracting domain: {}", err);
            "".to_string()
        }
    };
}

async fn handle_response(
    response: reqwest::Response,
    url: &str,
    pool: Arc<SqlitePool>,
    extractor: Arc<TldExtractor>,
    error_stats: ErrorStats,
    elapsed: f64,
) -> Result<(), Error> {
    let final_url = response.url().to_string();
    let status = response.status();
    let status_desc = status.canonical_reason().unwrap_or_else(|| "Unknown Status Code");

    let title = response.text().await.and_then(|body| Ok(extract_title(&body, &error_stats))).unwrap_or_default();

    let initial_domain = extract_domain(&extractor, &url);
    let final_domain = extract_domain(&extractor, &final_url);

    let timestamp = chrono::Utc::now().timestamp_millis();

    update_database(&initial_domain, &final_domain, status, status_desc, elapsed, &title, timestamp, &pool).await
}

async fn handle_http_request(
    client: Arc<reqwest::Client>,
    url: String,
    pool: Arc<SqlitePool>,
    extractor: Arc<TldExtractor>,
    error_stats: ErrorStats,
    start_time: std::time::Instant,
) -> Result<(), Error> {
    let res = client.get(&url).send().await;

    let elapsed = start_time.elapsed().as_secs_f64();

    match res {
        Ok(response) => {
            futures::future::Either::Left(handle_response(response, &url, pool, extractor, error_stats, elapsed))
        }
        Err(e) => {
            update_error_stats(&error_stats, &e);
            futures::future::Either::Right(futures::future::ready(Err(e.into())))
        }
    }.await
}

fn extract_title(html: &str, error_stats: &ErrorStats) -> String {
    let parsed_html = Html::parse_document(html);

    let selector = match Selector::parse("title") {
        Ok(selector) => selector,
        Err(_) => {
            update_title_extract_error(error_stats);
            return String::from("");
        }
    };

    match parsed_html.select(&selector).next() {
        Some(element) => element.inner_html(),
        None => {
            update_title_extract_error(error_stats);
            String::from("")
        }
    }
}

pub async fn process_url(
    url: String,
    client: Arc<reqwest::Client>,
    pool: Arc<SqlitePool>,
    extractor: Arc<TldExtractor>,
    error_stats: ErrorStats,
) {
    let retry_strategy = get_retry_strategy();

    let start_time = std::time::Instant::now();

    let future: Pin<Box<dyn Future<Output = Result<(), Error>> + Send>> = Box::pin(tokio_retry::Retry::spawn(retry_strategy, move || {
        let client = client.clone();
        let url = url.clone();
        let pool = pool.clone();
        let extractor = extractor.clone();
        let error_stats = error_stats.clone();

        handle_http_request(client, url, pool, extractor, error_stats, start_time)
    }));

    match future.await {
        Ok(_) => (),
        Err(e) => error!("Error after retries: {}", e),
    }
}
