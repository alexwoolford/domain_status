use std::sync::Arc;
use std::time::Duration;

use reqwest::ClientBuilder;
use simplelog::{ColorChoice, LevelFilter, TerminalMode, TermLogger};
use tldextract::{TldExtractor, TldOption};
use tokio::sync::Semaphore;

use crate::error_handling::InitializationError;

// Initializes the logger for the application with the provided configuration.
pub fn init_logger() -> Result<(), InitializationError> {
    let config = simplelog::Config::default();
    let term_logger = TermLogger::new(
        LevelFilter::Info,
        config,
        TerminalMode::Mixed,
        ColorChoice::Auto,
    );

    // Leak the logger so that it lives for the entire duration of the program
    let leaked_term_logger = Box::leak(term_logger);
    log::set_logger(leaked_term_logger)?;
    log::set_max_level(LevelFilter::Info);
    Ok(())
}

pub fn init_semaphore(count: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(count))
}

pub async fn init_client() -> Result<Arc<reqwest::Client>, reqwest::Error> {
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(10))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")
        .build()?;
    Ok(Arc::new(client))
}

pub fn init_extractor() -> Arc<TldExtractor> {
    Arc::new(TldExtractor::new(TldOption::default()))
}
