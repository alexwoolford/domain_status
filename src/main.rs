use std::fs::File;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::error;
use log::info;
use reqwest::ClientBuilder;
use scraper::{Html, Selector};
use simplelog::{ColorChoice, Config, LevelFilter, TerminalMode, TermLogger};
use sqlx::{Pool, Sqlite, SqlitePool};
use structopt::StructOpt;
use tldextract::{TldExtractor, TldOption};
use tokio::sync::Semaphore;

// constants
const SEMAPHORE_COUNT: usize = 100;
const LOG_INTERVAL: usize = 100;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "url_checker",
    about = "Checks a list of URLs for their status and redirection."
)]
struct Opt {
    /// File to read
    #[structopt(parse(from_os_str))]
    file: PathBuf,
}

#[derive(Clone)]
struct ErrorStats {
    connection_refused: Arc<AtomicUsize>,
    dns_error: Arc<AtomicUsize>,
    title_extract_error: Arc<AtomicUsize>,
    other_errors: Arc<AtomicUsize>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logger()?;

    let opt = Opt::from_args();
    let file = File::open(&opt.file)?;
    let reader = BufReader::new(file);

    let mut tasks = FuturesUnordered::new();

    let semaphore = init_semaphore(SEMAPHORE_COUNT);
    let client = init_client().await?;
    let extractor = init_extractor();

    let pool = init_db_pool().await?;
    create_table(&pool).await?;

    let start_time = std::time::Instant::now();
    let mut count = 0;
    let log_interval = LOG_INTERVAL;
    let mut processed_urls = 0;

    let error_stats = ErrorStats {
        connection_refused: Arc::new(AtomicUsize::new(0)),
        dns_error: Arc::new(AtomicUsize::new(0)),
        title_extract_error: Arc::new(AtomicUsize::new(0)),
        other_errors: Arc::new(AtomicUsize::new(0)),
    };

    for line in reader.lines() {
        let url = match line {
            Ok(line) => {
                if !line.starts_with("http://") && !line.starts_with("https://") {
                    format!("https://{}", line)
                } else {
                    line
                }
            }
            Err(_) => continue,
        };

        // Acquire the semaphore here, outside of the async block
        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();

        // Clone the variables here, before moving them into the async block
        let client_clone = Arc::clone(&client);
        let pool_clone = Arc::clone(&pool);
        let extractor_clone = Arc::clone(&extractor);
        let error_stats_clone = error_stats.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = permit;

            process_url(
                url,
                client_clone,
                pool_clone,
                extractor_clone,
                error_stats_clone,
            )
            .await
        }));

        count += 1;
        if count % log_interval == 0 {
            let elapsed = start_time.elapsed();
            let _lines_per_sec = processed_urls as f64 / elapsed.as_secs_f64();
            processed_urls += count;

            info!(
                "Processed {} lines in {:.2} seconds (~{:.2} lines/sec)",
                processed_urls,
                elapsed.as_secs_f64(),
                _lines_per_sec
            );
            count = 0;
        }
    }

    while let Some(_) = tasks.next().await {}

    if count > 0 {
        processed_urls += count;
        let elapsed = start_time.elapsed();
        let _lines_per_sec = processed_urls as f64 / elapsed.as_secs_f64();
    }

    info!("Error Summary:");
    info!(
        "Connection Refused: {}",
        error_stats.connection_refused.load(Ordering::SeqCst)
    );
    info!(
        "DNS Errors: {}",
        error_stats.dns_error.load(Ordering::SeqCst)
    );
    info!(
        "Other Errors: {}",
        error_stats.other_errors.load(Ordering::SeqCst)
    );
    info!(
        "Title extract error: {}",
        error_stats.title_extract_error.load(Ordering::SeqCst)
    );

    Ok(())
}

fn init_logger() -> Result<(), Box<dyn std::error::Error>> {
    let term_logger = TermLogger::new(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    );

    // Leak the logger so that it lives for the entire duration of the program
    let leaked_term_logger = Box::leak(term_logger);
    log::set_logger(leaked_term_logger)?;
    log::set_max_level(LevelFilter::Info);
    Ok(())
}

fn init_semaphore(count: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(count))
}

async fn init_client() -> Result<Arc<reqwest::Client>, reqwest::Error> {
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
        .build()?;
    Ok(Arc::new(client))
}

async fn init_db_pool() -> Result<Arc<Pool<Sqlite>>, sqlx::Error> {
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

    Ok(Arc::new(pool))
}

async fn create_table(pool: &Pool<Sqlite>) -> Result<(), Box<dyn std::error::Error>> {
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

fn init_extractor() -> Arc<TldExtractor> {
    Arc::new(TldExtractor::new(TldOption::default()))
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

async fn process_url(
    url: String,
    client: Arc<reqwest::Client>,
    pool: Arc<SqlitePool>,
    extractor: Arc<TldExtractor>,
    error_stats: ErrorStats,
) {
    let start_time = std::time::Instant::now();
    let res = client.get(&url).send().await;
    let elapsed = start_time.elapsed().as_secs_f64();

    match res {
        Ok(response) => {
            let final_url = response.url().to_string();
            let status = response.status();
            let status_desc = status.canonical_reason().unwrap_or("Unknown Status Code");

            let body = response.text().await.unwrap_or_default();
            let title = extract_title(&body, &error_stats);

            let initial_domain = extract_domain(&extractor, &url);
            let final_domain = extract_domain(&extractor, &final_url);

            let timestamp = chrono::Utc::now().timestamp_millis();

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
                .execute(pool.as_ref())
                .await {
                Ok(_) => (),
                Err(e) => {
                    error!("Error when accessing the database: {}", e);
                }
            }

        }
        Err(e) => {
            update_error_stats(&error_stats, &e);
        }
    }
}

fn update_error_stats(error_stats: &ErrorStats, error: &reqwest::Error) {
    if error.is_connect() {
        error_stats
            .connection_refused
            .fetch_add(1, Ordering::SeqCst);
    } else if error.is_timeout()
        || error
            .to_string()
            .contains("failed to lookup address information")
    {
        error_stats.dns_error.fetch_add(1, Ordering::SeqCst);
    } else {
        error_stats.other_errors.fetch_add(1, Ordering::SeqCst);
    }
}

fn update_title_extract_error(error_stats: &ErrorStats) {
    error_stats
        .title_extract_error
        .fetch_add(1, Ordering::SeqCst);
}

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

#[cfg(test)]
mod tests;
