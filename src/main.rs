use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::warn;
use log::info;
use structopt::StructOpt;

use config::*;
use database::*;
use initialization::*;
use utils::*;

mod config;
mod initialization;
mod database;
mod utils;
mod error_handling;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logger()?;

    let opt = Opt::from_args();
    let file = File::open(&opt.file)?;
    let reader = BufReader::new(file);

    let mut tasks = FuturesUnordered::new();

    let semaphore = init_semaphore(SEMAPHORE_LIMIT);

    let pool = init_db_pool().await?;
    let client = init_client().await?;
    let extractor = init_extractor();

    create_table(&pool).await?;

    let start_time = std::time::Instant::now();
    let log_interval = LOGGING_INTERVAL;

    let error_stats = ErrorStats {
        connection_refused: Arc::new(AtomicUsize::new(0)),
        dns_error: Arc::new(AtomicUsize::new(0)),
        title_extract_error: Arc::new(AtomicUsize::new(0)),
        other_errors: Arc::new(AtomicUsize::new(0)),
    };

    let rate_limiter = ErrorRateLimiter::new(error_stats.clone(), opt.error_rate);
    let completed_urls = Arc::new(AtomicUsize::new(0));

    for line in reader.lines() {
        let url = match line {
            Ok(line) => {
                if !line.starts_with("http://") && !line.starts_with("https://") {
                    format!("https://{}", line)
                } else {
                    line
                }
            }
            Err(e) => {
                warn!("Failed to read line from input file: {}", e);
                continue;
            }
        };

        rate_limiter.allow_operation().await;

        // Acquire the semaphore here, outside of the async block
        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();

        // Clone the variables here, before moving them into the async block
        let client_clone = Arc::clone(&client);
        let pool_clone = Arc::clone(&pool);
        let extractor_clone = Arc::clone(&extractor);
        let error_stats_clone = error_stats.clone();
        let completed_urls_clone = Arc::clone(&completed_urls);

        tasks.push(tokio::spawn(async move {
            let _permit = permit;

            match tokio::time::timeout(URL_PROCESSING_TIMEOUT, process_url(
                url,
                client_clone,
                pool_clone,
                extractor_clone,
                error_stats_clone,
            )).await {
                Ok(_) => {
                    completed_urls_clone.fetch_add(1, Ordering::SeqCst);

                    if completed_urls_clone.load(Ordering::SeqCst) % log_interval == 0 {
                        let elapsed = start_time.elapsed();
                        let completed = completed_urls_clone.load(Ordering::SeqCst);
                        info!(
                        "Processed {} lines in {:.2} seconds (~{:.2} lines/sec)",
                        completed,
                        elapsed.as_secs_f64(),
                        completed as f64 / elapsed.as_secs_f64()
                    );
                    }
                }
                Err(_) => {}
            }
        }));
    }

    while let Some(_) = tasks.next().await {}

    info!("Error Summary:");
    info!(
        "   Connection Refused: {}",
        error_stats.connection_refused.load(Ordering::SeqCst)
    );
    info!(
        "   DNS Errors: {}",
        error_stats.dns_error.load(Ordering::SeqCst)
    );
    info!(
        "   Other Errors: {}",
        error_stats.other_errors.load(Ordering::SeqCst)
    );
    info!(
        "   Title extract error: {}",
        error_stats.title_extract_error.load(Ordering::SeqCst)
    );

    Ok(())
}

#[cfg(test)]
mod tests;
