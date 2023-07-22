use futures::stream::FuturesUnordered;
use futures::StreamExt;
use reqwest::ClientBuilder;
use rusqlite::{params, Result};
use scraper::{Html, Selector};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use log::error;
use structopt::StructOpt;
use tldextract::{TldExtractor, TldOption};
use tokio::sync::{Semaphore};
use simplelog::{TermLogger, LevelFilter, Config, TerminalMode, ColorChoice};

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

#[derive(Default)]
struct ErrorCounts {
    connection_refused: u32,
    dns_error: u32,
    title_extract_error: u32,
    other_errors: u32,
}

#[derive(Clone, Default)]
struct ErrorStats {
    counts: Arc<Mutex<ErrorCounts>>,
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
    let pool = init_db_pool()?;
    let extractor = init_extractor();

    let pool_for_table = Arc::clone(&pool);

    tokio::task::spawn_blocking(move || {
        let conn = pool_for_table.get().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS url_status (
        id INTEGER PRIMARY KEY,
        domain TEXT NOT NULL,
        final_domain TEXT NOT NULL,
        status INTEGER NOT NULL,
        status_description TEXT NOT NULL,
        response_time NUMERIC(10, 2),
        title TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )",
            [],
        )
            .unwrap();
    })
        .await
        .unwrap();

    let start_time = std::time::Instant::now();
    let mut count = 0;
    let log_interval = LOG_INTERVAL;
    let mut processed_urls = 0;

    let error_stats = ErrorStats {
        counts: Arc::new(Mutex::new(ErrorCounts {
            connection_refused: 0,
            dns_error: 0,
            title_extract_error: 0,
            other_errors: 0,
        })),
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

        let client_clone = Arc::clone(&client);
        let pool_clone = Arc::clone(&pool);
        let extractor_clone = Arc::clone(&extractor);
        let error_stats_clone = error_stats.clone();
        let semaphore_clone = Arc::clone(&semaphore);

        // Acquire the semaphore here, outside of the async block
        let permit = semaphore_clone.acquire_owned().await.unwrap();

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

            println!(
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

    println!("Error Summary:");
    println!("Connection Refused: {}", error_stats.counts.lock().unwrap().connection_refused);
    println!("DNS Errors: {}", error_stats.counts.lock().unwrap().dns_error);
    println!("Other Errors: {}", error_stats.counts.lock().unwrap().other_errors);
    println!("Title extract error: {}", error_stats.counts.lock().unwrap().title_extract_error);

    Ok(())
}

fn init_logger() -> Result<(), Box<dyn std::error::Error>> {
    let _ = TermLogger::new(
        LevelFilter::Warn,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    );
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

fn init_db_pool() -> Result<Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>, r2d2::Error> {
    let manager = r2d2_sqlite::SqliteConnectionManager::file("url_checker.db");
    let pool = r2d2::Pool::new(manager)?;
    Ok(Arc::new(pool))
}

fn init_extractor() -> Arc<TldExtractor> {
    Arc::new(TldExtractor::new(TldOption::default()))
}

async fn process_url(
    url: String,
    client: Arc<reqwest::Client>,
    pool: Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
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
            let status_desc = get_status_description(status.as_u16());
            let body = response.text().await.unwrap_or_default();

            match tokio::task::spawn_blocking(move || -> anyhow::Result<()> {

                let initial_domain = extract_domain(&extractor, &url);
                let final_domain = extract_domain(&extractor, &final_url);

                let conn = pool.get().map_err(|e| anyhow::anyhow!("Failed to get connection from the pool: {}", e))?;
                let document = Html::parse_document(&body);
                let selector = Selector::parse("title").unwrap();
                let title = document.select(&selector)
                    .next()
                    .map_or_else(|| {
                        update_title_extract_error(&error_stats);
                        "".to_string()
                    }, |e| e.inner_html());

                let timestamp = chrono::Utc::now().to_rfc3339();

                // Insert the result into the SQLite database
                conn.execute(
                    "INSERT INTO url_status (domain, final_domain, status, status_description, response_time, title, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![initial_domain, final_domain, status.as_u16(), status_desc, elapsed, title, timestamp],
                ).map_err(|e| anyhow::anyhow!("Error when writing to the database: {}", e))?;

                Ok(())
            }).await {
                Ok(result) => {
                    match result {
                        Ok(_) => (),
                        Err(e) => {
                            error!("Error when accessing the database: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Error when accessing the database: {}", e);
                }
            };
        }
        Err(e) => {
            update_error_stats(&error_stats, &e);
        }
    }
}

fn update_error_stats(error_stats: &ErrorStats, error: &reqwest::Error) {
    let mut counts = error_stats.counts.lock().unwrap();
    if error.is_connect() {
        counts.connection_refused += 1;
    } else if error.is_timeout() {
        counts.dns_error += 1;
    } else if error.to_string().contains("failed to lookup address information") {
        counts.dns_error += 1;
    } else {
        counts.other_errors += 1;
    }
}

fn update_title_extract_error(error_stats: &ErrorStats) {
    let mut counts = error_stats.counts.lock().unwrap();
    counts.title_extract_error += 1;
}

fn extract_domain(extractor: &TldExtractor, url: &str) -> String {
    match extractor.extract(url) {
        Ok(extract) => {
            if let Some(main_domain) = extract.domain {
                return format!(
                    "{}.{}",
                    main_domain.to_lowercase(),
                    extract.suffix.unwrap_or_default()
                );
            } else {
                // Domain not present in the URL, return an empty string
                return "".to_string();
            }
        }
        Err(err) => {
            error!("Error when extracting domain: {}", err);
            return "".to_string();
        }
    }
}

fn get_status_description(status_code: u16) -> String {
    match status_code {
        100 => "Continue".to_string(),
        101 => "Switching Protocols".to_string(),
        102 => "Processing".to_string(),
        103 => "Early Hints".to_string(),
        200 => "OK".to_string(),
        201 => "Created".to_string(),
        202 => "Accepted".to_string(),
        203 => "Non-Authoritative Information".to_string(),
        204 => "No Content".to_string(),
        205 => "Reset Content".to_string(),
        206 => "Partial Content".to_string(),
        207 => "Multi-Status".to_string(),
        208 => "Already Reported".to_string(),
        226 => "IM Used".to_string(),
        300 => "Multiple Choices".to_string(),
        301 => "Moved Permanently".to_string(),
        302 => "Found".to_string(),
        303 => "See Other".to_string(),
        304 => "Not Modified".to_string(),
        305 => "Use Proxy".to_string(),
        307 => "Temporary Redirect".to_string(),
        308 => "Permanent Redirect".to_string(),
        400 => "Bad Request".to_string(),
        401 => "Unauthorized".to_string(),
        402 => "Payment Required".to_string(),
        403 => "Forbidden".to_string(),
        404 => "Not Found".to_string(),
        405 => "Method Not Allowed".to_string(),
        406 => "Not Acceptable".to_string(),
        407 => "Proxy Authentication Required".to_string(),
        408 => "Request Timeout".to_string(),
        409 => "Conflict".to_string(),
        410 => "Gone".to_string(),
        411 => "Length Required".to_string(),
        412 => "Precondition Failed".to_string(),
        413 => "Content Too Large".to_string(),
        414 => "URI Too Long".to_string(),
        415 => "Unsupported Media Type".to_string(),
        416 => "Range Not Satisfiable".to_string(),
        417 => "Expectation Failed".to_string(),
        421 => "Misdirected Request".to_string(),
        422 => "Unprocessable Content".to_string(),
        423 => "Locked".to_string(),
        424 => "Failed Dependency".to_string(),
        425 => "Too Early".to_string(),
        426 => "Upgrade Required".to_string(),
        428 => "Precondition Required".to_string(),
        429 => "Too Many Requests".to_string(),
        431 => "Request Header Fields Too Large".to_string(),
        451 => "Unavailable For Legal Reasons".to_string(),
        500 => "Internal Server Error".to_string(),
        501 => "Not Implemented".to_string(),
        502 => "Bad Gateway".to_string(),
        503 => "Service Unavailable".to_string(),
        504 => "Gateway Timeout".to_string(),
        505 => "HTTP Version Not Supported".to_string(),
        506 => "Variant Also Negotiates".to_string(),
        507 => "Insufficient Storage".to_string(),
        508 => "Loop Detected".to_string(),
        510 => "Not Extended".to_string(),
        511 => "Network Authentication Required".to_string(),
        _ => format!("Status code: {}", status_code),
    }
}
