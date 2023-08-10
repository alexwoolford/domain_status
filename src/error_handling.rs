use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use log::warn;
use tokio_retry::strategy::ExponentialBackoff;

use crate::config::LOGGING_INTERVAL;

#[derive(Clone)]
pub struct ErrorStats {
    pub connection_refused: Arc<AtomicUsize>,
    pub processing_timeouts: Arc<AtomicUsize>,
    pub dns_error: Arc<AtomicUsize>,
    pub title_extract_error: Arc<AtomicUsize>,
    pub too_many_redirects: Arc<AtomicUsize>,
    pub other_errors: Arc<AtomicUsize>,
}

impl ErrorStats {
    pub fn increment_connection_refused(&self) {
        self.connection_refused.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_processing_timeouts(&self) {
        self.processing_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_dns_error(&self) {
        self.dns_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_title_extract_error(&self) {
        self.title_extract_error.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_too_many_redirects(&self) {
        self.too_many_redirects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_other_errors(&self) {
        self.other_errors.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct ErrorRateLimiter {
    pub error_stats: Arc<ErrorStats>,
    operation_count: Arc<AtomicUsize>,
    error_rate: Arc<AtomicUsize>,
    error_rate_threshold: f64,
}

impl ErrorRateLimiter {
    pub fn new(error_stats: Arc<ErrorStats>, error_rate_threshold: f64) -> Self {
        ErrorRateLimiter {
            error_stats,
            operation_count: Arc::new(AtomicUsize::new(0)),
            error_rate: Arc::new(AtomicUsize::new(0)),
            error_rate_threshold,
        }
    }

    pub async fn allow_operation(&self) {
        self.operation_count.fetch_add(1, Ordering::SeqCst);

        if self.operation_count.load(Ordering::SeqCst) % LOGGING_INTERVAL == 0 {
            let error_rate = self.calculate_error_rate();

            self.error_rate.store(error_rate as usize, Ordering::SeqCst);

            let total_errors = self.error_stats.connection_refused.load(Ordering::SeqCst)
                + self.error_stats.dns_error.load(Ordering::SeqCst)
                + self.error_stats.other_errors.load(Ordering::SeqCst)
                + self.error_stats.title_extract_error.load(Ordering::SeqCst);

            if error_rate > self.error_rate_threshold {
                // increase backoff time
                let sleep_duration = Duration::from_secs_f64((error_rate / 5.0).max(1.0));
                warn!("Throttled; error rate of {:.2}% has exceeded the set threshold. There were {} errors out of {} operations. Backoff time is {:.2} seconds.",
        error_rate, total_errors, self.operation_count.load(Ordering::SeqCst), sleep_duration.as_secs_f64());
                tokio::time::sleep(sleep_duration).await;
            }
        }
    }

    fn calculate_error_rate(&self) -> f64 {
        let total_errors = self.error_stats.connection_refused.load(Ordering::SeqCst)
            + self.error_stats.dns_error.load(Ordering::SeqCst)
            + self.error_stats.other_errors.load(Ordering::SeqCst)
            + self.error_stats.title_extract_error.load(Ordering::SeqCst);

        let error_rate = (total_errors as f64 / f64::max(total_errors as f64, self.operation_count.load(Ordering::SeqCst) as f64)) * 100.0;

        error_rate
    }
}

#[derive(Debug)]
pub enum InitializationError {
    LoggerError(log::SetLoggerError),
}

impl From<log::SetLoggerError> for InitializationError {
    fn from(err: log::SetLoggerError) -> InitializationError {
        InitializationError::LoggerError(err)
    }
}

impl fmt::Display for InitializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InitializationError::LoggerError(e) => write!(f, "Logger initialization error: {}", e),
        }
    }
}

impl std::error::Error for InitializationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InitializationError::LoggerError(e) => Some(e),
        }
    }
}

pub fn get_retry_strategy() -> ExponentialBackoff {
    ExponentialBackoff::from_millis(1000)
        .factor(2)                // Double the delay with each retry
        .max_delay(Duration::from_secs(20)) // Maximum delay of 20 seconds
}

pub fn update_error_stats(error_stats: &ErrorStats, error: &reqwest::Error) {
    if error.is_connect() {
        error_stats.increment_connection_refused();
    } else if error.is_timeout()
        || error
        .to_string()
        .contains("failed to lookup address information")
    {
        error_stats.increment_dns_error();
    } else if error.is_redirect()
        || error
        .to_string()
        .contains("too many redirects")
    {
        error_stats.increment_too_many_redirects();
    } else {
        error_stats.increment_other_errors();
    }
}
