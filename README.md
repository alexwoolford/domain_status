# domain_status

This is a multi-threaded tool implemented in Rust for checking the status and redirection of a list of URLs. It provides performance monitoring, error handling, and stores the result in a SQLite database.

## Features
- Multithreading using tokio and futures.
- Error handling for various types of issues such as connection refused, DNS errors, etc.
- Extraction of domain from URLs using tldextract library.
- Extraction and storage of the status, final domain after redirection, and title of the webpage.
- Status updates for every 100 URLs processed.
- Error summary at the end of the execution.

## Dependencies
This program depends on several crates including:
- futures
- reqwest
- rusqlite
- scraper
- std
- log
- structopt
- tldextract
- tokio
- simplelog

## Usage

Here, `file` is the name of the file containing the URLs to be checked.

## Output

The output of the program includes:
- Logs for every 100 URLs processed, including the elapsed time and the average processing speed.
- A summary of the errors encountered during execution.

The results of the check are stored in a SQLite database in a table named `url_status`. Each entry in the table includes the following fields:
- `id` (integer)
- `domain` (text)
- `final_domain` (text)
- `status` (integer)
- `status_description` (text)
- `response_time` (text)
- `title` (text)

## Errors

The program keeps track of four types of errors:
- `connection_refused`
- `dns_error`
- `title_extract_error`
- `other_errors`

The error counts are output at the end of the program execution.

## Initialization

The program initializes a logger, a semaphore, an HTTP client, a database connection pool, and a domain extractor.

## Processing

Each URL is processed in the `process_url` function, which:
- Sends a GET request to the URL.
- Extracts the status, final URL after redirection, and the page title.
- Stores these details in the `url_status` table in the database.

## Note
This program does not currently handle the possibility of failing to open the input file. It also does not handle the possibility of an HTTP request failing.
