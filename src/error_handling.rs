use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use strum::IntoEnumIterator;
use log::warn;
use tokio_retry::strategy::ExponentialBackoff;
use strum_macros::EnumIter as EnumIterMacro;


use crate::config::LOGGING_INTERVAL;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIterMacro)]
pub enum ErrorType {
    ConnectionRefused,
    ProcessingTimeouts,
    DNSError,
    TitleExtractError,
    TooManyRedirects,
    OtherErrors,
}

pub struct ErrorStats {
    errors: HashMap<ErrorType, AtomicUsize>,
}

impl ErrorStats {
    pub fn new() -> Self {
        let mut errors = HashMap::new();
        for error in ErrorType::iter() {
            errors.insert(error, AtomicUsize::new(0));
        }
        ErrorStats { errors }
    }

    pub fn increment(&self, error: ErrorType) {
        if let Some(counter) = self.errors.get(&error) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn get_count(&self, error: ErrorType) -> usize {
        if let Some(counter) = self.errors.get(&error) {
            counter.load(Ordering::SeqCst)
        } else {
            0
        }
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

            let total_errors = self.error_stats.get_count(ErrorType::ConnectionRefused)
                + self.error_stats.get_count(ErrorType::DNSError)
                + self.error_stats.get_count(ErrorType::OtherErrors)
                + self.error_stats.get_count(ErrorType::TitleExtractError);

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
        let total_errors = self.error_stats.get_count(ErrorType::ConnectionRefused)
            + self.error_stats.get_count(ErrorType::DNSError)
            + self.error_stats.get_count(ErrorType::OtherErrors)
            + self.error_stats.get_count(ErrorType::TitleExtractError);

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
    let error_type = if error.is_connect() {
        ErrorType::ConnectionRefused
    } else if error.is_timeout() || error.to_string().contains("failed to lookup address information") {
        ErrorType::DNSError
    } else if error.is_redirect() || error.to_string().contains("too many redirects") {
        ErrorType::TooManyRedirects
    } else {
        ErrorType::OtherErrors
    };
    error_stats.increment(error_type);
}
