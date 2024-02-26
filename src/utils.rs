use std::sync::Arc;
use anyhow::{Result, Error};
use scraper::{Html, Selector};
use log::{info, error};
use sqlx::SqlitePool;
use structopt::lazy_static::lazy_static;
use tldextract::TldExtractor;
use tokio::io::AsyncWriteExt;
use rustls::{RootCertStore};
use tokio_rustls::TlsConnector;
use std::convert::TryInto;
use rustls::pki_types::ServerName;
use validators::serde_json::json;
use x509_parser::extensions::ParsedExtension;

use crate::database::update_database;
use crate::error_handling::{ErrorStats, ErrorType, get_retry_strategy, update_error_stats};
use crate::item_counting::{OidCounts};

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

fn is_ev_certificate(cert: &x509_parser::certificate::X509Certificate, oid_counts: &mut &OidCounts) -> bool {
    // List of some known EV OIDs. You would need to maintain and update this list.
    let known_ev_oids = vec![
        "2.16.840.1.114412.2.1",
        "2.23.140.1.1",
        "1.3.6.1.4.1.6334.1.100.1",
        "2.16.840.1.113733.1.7.23.6",
        "2.16.840.1.114412.3.2",
        "2.23.140.1.3",
        // ... add other known EV OIDs here ...
        // ref: https://github.com/digicert/digicert_official_oids
    ];

    for ext in cert.extensions() {

        oid_counts.increment(&ext.oid.to_string());
        // oid_counts.increment(ext.oid.to_id_string());

        if ext.oid == x509_parser::oid_registry::OID_X509_EXT_CERTIFICATE_POLICIES {
            // Here, we identified the CertificatePolicies extension by OID.
            // If x509_parser does not provide parsing, you might not get the parsed_content.
            // Instead, we'll just look at the raw value (which is a byte slice) and check if any known EV OIDs appear.
            // This is a naive check and assumes no other data would collide with the OID strings.
            for oid in &known_ev_oids {
                if ext.value.windows(oid.as_bytes().len()).any(|window| window == oid.as_bytes()) {
                    return true;
                }
            }
        }
    }
    false
}

async fn handle_response(
    response: reqwest::Response,
    url: &str,
    pool: &SqlitePool,
    extractor: &TldExtractor,
    error_stats: &ErrorStats,
    oid_counts: &OidCounts,
    elapsed: f64,
) -> Result<(), Error> {
    let (subject, issuer, valid_from, valid_to, is_ev) = if url.starts_with("https://") {
        match extract_domain(&extractor, url) {
            Ok(domain) => match get_ssl_certificate_info(&domain, oid_counts).await {
                Ok(cert_info) => (cert_info.subject, cert_info.issuer, cert_info.valid_from, cert_info.valid_to, cert_info.is_ev),
                Err(e) => {
                    error!("Failed to get SSL certificate info for {}: {}", domain, e);
                    (None, None, None, None, None)
                }
            },
            Err(_) => (None, None, None, None, None),
        }
    } else {
        (None, None, None, None, None)
    };

    let final_url = response.url().to_string();
    let status = response.status();
    let status_desc = status.canonical_reason().unwrap_or_else(|| "Unknown Status Code");

    let title = response.text().await.map(|body| extract_title(&body, error_stats)).unwrap_or_default();

    let initial_domain = extract_domain(&extractor, url)?;
    let final_domain = extract_domain(&extractor, &final_url)?;

    let timestamp = chrono::Utc::now().timestamp_millis();

    update_database(&initial_domain, &final_domain, status, status_desc, elapsed, &title, timestamp, &subject, &issuer, valid_from, valid_to, is_ev, pool).await
}


async fn handle_http_request(
    client: &reqwest::Client,
    url: &str,
    pool: &SqlitePool,
    extractor: &TldExtractor,
    error_stats: &ErrorStats,
    oid_counts: &OidCounts,
    start_time: std::time::Instant,
) -> Result<(), Error> {
    let res = client.get(url).send().await;
    let elapsed = start_time.elapsed().as_secs_f64();

    match res {
        Ok(response) => handle_response(response, url, pool, extractor, error_stats, oid_counts, elapsed).await,
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
    subject: Option<String>,
    issuer: Option<String>,
    valid_from: Option<chrono::NaiveDateTime>,
    valid_to: Option<chrono::NaiveDateTime>,
    is_ev: Option<bool>
}

fn extract_certificate_policies(cert: &x509_parser::certificate::X509Certificate<'_>) -> Result<Vec<String>, anyhow::Error> {
    let mut oids: Vec<String> = Vec::new();

    for ext in cert.extensions() {
        // Dereference the result from parsed_extension()
        match *ext.parsed_extension() {
            // Now match against the ParsedExtension variants directly
            ParsedExtension::CertificatePolicies(ref policies) => {
                // Now we can iterate over the policies
                oids.extend(policies.iter().map(|policy| policy.policy_id.to_string()));
            },
            // Ignore other cases; we only care about CertificatePolicies
            _ => {}
        }
    }

    Ok(oids)
}



async fn get_ssl_certificate_info(domain: &str, mut oid_counts: &OidCounts) -> Result<CertificateInfo, anyhow::Error> {

    info!("{}", domain);

    let mut root_store = RootCertStore::empty();
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
    );

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let config_arc = Arc::new(config);
    let domain_owned = domain.to_string(); // Convert &str to String
    let server_name: ServerName = domain_owned.try_into().unwrap();
    let server_name_clone = server_name.clone();

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

    if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
        if let Some(cert) = certs.last() {
            let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref())?;
            let tbs_cert = &cert.tbs_certificate;

            let subject = cert.tbs_certificate.subject.to_string();
            let issuer = cert.tbs_certificate.issuer.to_string();

            let sig_algorithm_oid = cert.signature_algorithm.algorithm.clone();
            let sig_algorithm_string = format!("{}", sig_algorithm_oid);

            let oids = extract_certificate_policies(&cert);

            // TODO: sometimes there are multiple OIDs, and even multiple records for a single domain. These need to be collapsed into a single list.
            match oids {
                Ok(oids) => {
                    // Now we have a `Vec<String>` that we can serialize
                    match serde_json::to_string(&oids) {
                        Ok(json_string) => {
                            println!("Serialized JSON string: {}", json_string);
                            // You can now store `json_string` in your database or use it as needed
                        },
                        Err(e) => {
                            println!("Serialization error: {}", e);
                            // Handle serialization error, such as logging or returning the error
                        },
                    }
                },
                Err(e) => {
                    // Handle the error that occurred during OID extraction
                    println!("Error extracting OIDs: {}", e);
                    // Depending on your error handling, you may log the error, return it, etc.
                },
            }

            let is_ev = is_ev_certificate(&cert, &mut oid_counts);

            let valid_from_str = tbs_cert.validity.not_before.to_rfc2822()
                .map_err(|e| anyhow::anyhow!("RFC2822 conversion error for not_before: {}", e))?;
            let valid_from = chrono::NaiveDateTime::parse_from_str(&valid_from_str, "%a, %d %b %Y %H:%M:%S %z")
                .map_err(|_| anyhow::anyhow!("Failed to parse not_before"))?;

            let valid_to_str = tbs_cert.validity.not_after.to_rfc2822()
                .map_err(|e| anyhow::anyhow!("RFC2822 conversion error for not_after: {}", e))?;
            let valid_to = chrono::NaiveDateTime::parse_from_str(&valid_to_str, "%a, %d %b %Y %H:%M:%S %z")
                .map_err(|_| anyhow::anyhow!("Failed to parse not_after"))?;

            return Ok(CertificateInfo {
                subject:Some(subject),
                issuer: Some(issuer),
                valid_from: Some(valid_from),
                valid_to: Some(valid_to),
                is_ev: Some(is_ev),
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
    oid_counts: Arc<OidCounts>,
) {
    let retry_strategy = get_retry_strategy();
    let start_time = std::time::Instant::now();

    let future = tokio_retry::Retry::spawn(retry_strategy, || {
        let client = client.clone();
        let url = url.clone();
        let pool = pool.clone();
        let extractor = extractor.clone();
        let error_stats = error_stats.clone();
        let oid_counts = oid_counts.clone();

        tokio::task::spawn(async move {
            handle_http_request(&*client, &url, &*pool, &*extractor, &error_stats, &oid_counts, start_time).await
        })
    });

    match future.await {
        Ok(_) => {}
        Err(e) => error!("Error after retries: {}", e),
    }
}
