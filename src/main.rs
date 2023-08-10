use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::info;
use log::warn;
use structopt::StructOpt;
use validators::regex::Regex;

use config::*;
use database::*;
use initialization::*;
use utils::*;

use crate::error_handling::{ErrorRateLimiter, ErrorStats};

mod config;
mod initialization;
mod database;
mod utils;
mod error_handling;

fn log_progress(start_time: std::time::Instant, completed_urls: &Arc<AtomicUsize>) {
    let elapsed = start_time.elapsed();
    let completed = completed_urls.load(Ordering::SeqCst);
    info!(
        "Processed {} lines in {:.2} seconds (~{:.2} lines/sec)",
        completed,
        elapsed.as_secs_f64(),
        completed as f64 / elapsed.as_secs_f64()
    );
}

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

    let error_stats = Arc::new(ErrorStats {
        connection_refused: Arc::new(AtomicUsize::new(0)),
        processing_timeouts: Arc::new(AtomicUsize::new(0)),
        dns_error: Arc::new(AtomicUsize::new(0)),
        title_extract_error: Arc::new(AtomicUsize::new(0)),
        too_many_redirects: Arc::new(AtomicUsize::new(0)),
        other_errors: Arc::new(AtomicUsize::new(0)),
    });

    let rate_limiter = ErrorRateLimiter::new(error_stats.clone(), opt.error_rate);

    let completed_urls = Arc::new(AtomicUsize::new(0));

    let url_regex = Regex::new(r"^https?://").unwrap();

    for line in reader.lines() {
        let url = match line {
            Ok(line) => {
                if !url_regex.is_match(&line) {
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

        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();

        let client_clone = Arc::clone(&client);
        let pool_clone = Arc::clone(&pool);
        let extractor_clone = Arc::clone(&extractor);
        // Clone for use inside the async block
        let error_stats_inside = error_stats.clone();

        let completed_urls_clone = Arc::clone(&completed_urls);

        let error_stats_for_timeout = error_stats_inside.clone();

        tasks.push(tokio::spawn(async move {
            let _permit = permit;

            let result = tokio::time::timeout(URL_PROCESSING_TIMEOUT, process_url(
                url,
                client_clone,
                pool_clone,
                extractor_clone,
                error_stats_for_timeout,
            )).await;

            match result {
                Ok(()) => {
                    completed_urls_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(_) => {
                    error_stats_inside.increment_processing_timeouts();
                }
            }
        }));
    }

    // Clone the Arc before the logging task
    let completed_urls_clone_for_logging = Arc::clone(&completed_urls);

    let logging_task = tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(LOGGING_INTERVAL as u64));
        loop {
            interval.tick().await;
            log_progress(start_time, &completed_urls_clone_for_logging);
        }
    });

    while let Some(_) = tasks.next().await {}

    // Ensure the logging task is done before exiting
    drop(logging_task);

    // Log one final time before printing the error summary
    log_progress(start_time, &completed_urls);

    info!("Error Summary:");
    info!(
        "   Connection Refused: {}",
        error_stats.connection_refused.load(Ordering::SeqCst)
    );
    info!(
        "   Processing Timeouts: {}",
        error_stats.processing_timeouts.load(Ordering::SeqCst)
    );
    info!(
        "   DNS Errors: {}",
        error_stats.dns_error.load(Ordering::SeqCst)
    );
    info!(
        "   Title extract error: {}",
        error_stats.title_extract_error.load(Ordering::SeqCst)
    );
    info!(
        "   Too many redirects: {}",
        error_stats.too_many_redirects.load(Ordering::SeqCst)
    );
    info!(
        "   Other Errors: {}",
        error_stats.other_errors.load(Ordering::SeqCst)
    );

    Ok(())
}

#[cfg(test)]
mod tests;
