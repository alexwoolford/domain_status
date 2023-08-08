use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use log::warn;
use structopt::StructOpt;

// constants
pub const SEMAPHORE_LIMIT: usize = 500;
pub const LOGGING_INTERVAL: usize = 100;
pub const URL_PROCESSING_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default, Debug, StructOpt)]
#[structopt(name = "domain_status", about = "Checks a list of URLs for their status and redirection.")]
pub struct Opt {
    /// File to read
    #[structopt(parse(from_os_str))]
    pub file: PathBuf, // Make this field public

    /// Error rate threshold
    #[structopt(long, default_value = "60.0")]
    pub error_rate: f64, // Make this field public
}

#[derive(Clone)]
pub struct ErrorStats {
    pub connection_refused: Arc<AtomicUsize>, // Make this field public
    pub dns_error: Arc<AtomicUsize>,          // Make this field public
    pub title_extract_error: Arc<AtomicUsize>,// Make this field public
    pub other_errors: Arc<AtomicUsize>,       // Make this field public
}

#[derive(Clone)]
pub struct ErrorRateLimiter {
    pub error_stats: ErrorStats,              // Make this field public
    operation_count: Arc<AtomicUsize>,
    error_rate: Arc<AtomicUsize>,
    error_rate_threshold: f64,
}

impl ErrorRateLimiter {
    pub fn new(error_stats: ErrorStats, error_rate_threshold: f64) -> Self { // Make this function public
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