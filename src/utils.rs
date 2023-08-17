use std::sync::Arc;
use anyhow::{Result, Error};
use scraper::{Html, Selector};
use log::{info, error};
use sqlx::SqlitePool;
use structopt::lazy_static::lazy_static;
use tldextract::TldExtractor;
use tokio::io::AsyncWriteExt;
use rustls::{OwnedTrustAnchor, RootCertStore, ServerName};
use tokio_rustls::TlsConnector;
use std::convert::TryInto;

use crate::database::update_database;
use crate::error_handling::{ErrorStats, ErrorType, get_retry_strategy, update_error_stats};

lazy_static! {
    static ref TITLE_SELECTOR: Selector = Selector::parse("title").unwrap();
}

fn extract_domain(extractor: &TldExtractor, url: &str) -> Result<String, anyhow::Error> {
    extractor.extract(url)
        .map_err(|e| anyhow::anyhow!("Extractor error: {}", e))
        .and_then(|extract| {
            if let Some(main_domain) = extract.domain {
                Ok(format!(
                    "{}.{}",
                    main_domain.to_lowercase(),
                    extract.suffix.unwrap_or_default()
                ))
            } else {
                // Domain not present in the URL, return an error
                Err(anyhow::anyhow!("Failed to extract domain from {}", url))
            }
        })
}

async fn handle_response(
    response: reqwest::Response,
    url: &str,
    pool: &SqlitePool,
    extractor: &TldExtractor,
    error_stats: &ErrorStats,
    elapsed: f64,
) -> Result<(), Error> {
    let (issuer, valid_from, valid_to) = if url.starts_with("https://") {
        match extract_domain(&extractor, url) {
            Ok(domain) => match get_ssl_certificate_info(&domain).await {
                Ok(cert_info) => (cert_info.issuer, cert_info.valid_from, cert_info.valid_to),
                Err(e) => {
                    error!("Failed to get SSL certificate info for {}: {}", domain, e);
                    (None, None, None)
                }
            },
            Err(_) => (None, None, None),
        }
    } else {
        (None, None, None)
    };

    let final_url = response.url().to_string();
    let status = response.status();
    let status_desc = status.canonical_reason().unwrap_or_else(|| "Unknown Status Code");

    let title = response.text().await.map(|body| extract_title(&body, error_stats)).unwrap_or_default();

    let initial_domain = extract_domain(&extractor, url)?;
    let final_domain = extract_domain(&extractor, &final_url)?;

    let timestamp = chrono::Utc::now().timestamp_millis();

    update_database(&initial_domain, &final_domain, status, status_desc, elapsed, &title, timestamp, &issuer, valid_from, valid_to, pool).await
}


async fn handle_http_request(
    client: &reqwest::Client,
    url: &str,
    pool: &SqlitePool,
    extractor: &TldExtractor,
    error_stats: &ErrorStats,
    start_time: std::time::Instant,
) -> Result<(), Error> {
    let res = client.get(url).send().await;
    let elapsed = start_time.elapsed().as_secs_f64();

    match res {
        Ok(response) => handle_response(response, url, pool, extractor, error_stats, elapsed).await,
        Err(e) => {
            update_error_stats(error_stats, &e);
            Err(e.into())
        }
    }
}

fn extract_title(html: &str, error_stats: &ErrorStats) -> String {
    let parsed_html = Html::parse_document(html);

    // Use the pre-created selector.
    match parsed_html.select(&TITLE_SELECTOR).next() {
        Some(element) => element.inner_html().trim().to_string(),
        None => {
            error_stats.increment(ErrorType::TitleExtractError);
            String::from("")
        }
    }
}

struct CertificateInfo {
    issuer: Option<String>,
    valid_from: Option<chrono::NaiveDateTime>,
    valid_to: Option<chrono::NaiveDateTime>,
}

async fn get_ssl_certificate_info(domain: &str) -> Result<CertificateInfo, anyhow::Error> {

    info!("{}", domain);

    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
    );
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let config_arc = Arc::new(config);
    let server_name: ServerName = domain.try_into().unwrap();
    let server_name_clone = server_name.clone();

    let conn = rustls::ClientConnection::new(config_arc.clone(), server_name).unwrap();

    let sock = tokio::net::TcpStream::connect(format!("{}:443", domain)).await?;

    let mut tls_stream = TlsConnector::from(config_arc.clone()).connect(server_name_clone, sock).await?;

    let request = format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: close\r\n\
         Accept-Encoding: identity\r\n\
         \r\n",
        domain
    );

    tls_stream.write_all(request.as_bytes()).await?;

    // Destructure the result of get_ref() to clearly name the parts
    let (tcp_stream, client_session) = tls_stream.get_ref();

    if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
        if let Some(cert) = certs.last() {
            let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref())?;
            let tbs_cert = cert.tbs_certificate;

            let subject = tbs_cert.subject.to_string();
            let issuer = tbs_cert.issuer.to_string();

            let valid_from_str = tbs_cert.validity.not_before.to_rfc2822()
                .map_err(|e| anyhow::anyhow!("RFC2822 conversion error for not_before: {}", e))?;
            let valid_from = chrono::NaiveDateTime::parse_from_str(&valid_from_str, "%a, %d %b %Y %H:%M:%S %z")
                .map_err(|_| anyhow::anyhow!("Failed to parse not_before"))?;

            let valid_to_str = tbs_cert.validity.not_after.to_rfc2822()
                .map_err(|e| anyhow::anyhow!("RFC2822 conversion error for not_after: {}", e))?;
            let valid_to = chrono::NaiveDateTime::parse_from_str(&valid_to_str, "%a, %d %b %Y %H:%M:%S %z")
                .map_err(|_| anyhow::anyhow!("Failed to parse not_after"))?;

            return Ok(CertificateInfo {
                issuer: Some(issuer),
                valid_from: Some(valid_from),
                valid_to: Some(valid_to),
            });
        }
    }

    Err(anyhow::anyhow!("Failed to retrieve certificate information for {}", domain))

}

pub async fn process_url(
    url: String,
    client: Arc<reqwest::Client>,
    pool: Arc<SqlitePool>,
    extractor: Arc<TldExtractor>,
    error_stats: Arc<ErrorStats>,
) {
    let retry_strategy = get_retry_strategy();
    let start_time = std::time::Instant::now();

    let future = tokio_retry::Retry::spawn(retry_strategy, || {
        let client = client.clone();
        let url = url.clone();
        let pool = pool.clone();
        let extractor = extractor.clone();
        let error_stats = error_stats.clone();

        tokio::task::spawn(async move {
            handle_http_request(&*client, &url, &*pool, &*extractor, &error_stats, start_time).await
        })
    });

    match future.await {
        Ok(_) => {}
        Err(e) => error!("Error after retries: {}", e),
    }
}
