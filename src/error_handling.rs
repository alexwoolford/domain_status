use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio_retry::strategy::ExponentialBackoff;
use crate::config::ErrorStats;

pub fn get_retry_strategy() -> ExponentialBackoff {
    ExponentialBackoff::from_millis(1000)
        .factor(2)                // Double the delay with each retry
        .max_delay(Duration::from_secs(20)) // Maximum delay of 20 seconds
}

pub fn update_error_stats(error_stats: &ErrorStats, error: &reqwest::Error) {
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

pub fn update_title_extract_error(error_stats: &ErrorStats) {
    error_stats
        .title_extract_error
        .fetch_add(1, Ordering::SeqCst);
}
