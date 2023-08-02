# domain_status
This is a multithreaded tool implemented in Rust for checking the status and redirection of a list of URLs. It provides performance monitoring, error handling, and stores the result in a SQLite database.

## Features
Multithreading using tokio and futures for high-performance processing.
Comprehensive error handling for various types of connection and DNS issues.
Extraction of the domain from URLs using the tldextract library.
Extraction and storage of critical data such as the status, final domain after redirection, and the title of the webpage.
Regular status updates for every 100 URLs processed.
Comprehensive error summary at the end of the execution for debugging and auditing purposes.

## Dependencies
This program depends on several Rust crates, including but not limited to futures for asynchronous programming, reqwest for making HTTP requests, rusqlite for interacting with SQLite databases, scraper for web scraping, log for logging, structopt for command-line option parsing, tldextract for domain extraction, tokio for asynchronous I/O, and simplelog for simple and efficient logging.

## Building
This project uses Cargo, the Rust package manager, for building and dependency management.

To build the project, navigate to the project's root directory and use the following command:

    cargo build --release

This will create an executable in the `./target/release/` directory.

## Usage
To use the tool, provide the file containing the list of URLs to be checked as a command-line argument when running the program. For instance:

    domain_status urls.txt

Where `urls.txt` is a plain text file containing one URL per line, like so:

    https://example1.com
    https://example2.com

The program will process each URL asynchronously and store the results in the database.

You can also set an optional error-rate threshold using the `--error-rate` flag, like so:

    domain_status urls.txt --error-rate 60 

This sets an error-rate threshold of 60%. If the error-rate exceeds this threshold, the program will start to throttle the processing, slowing down the rate at which URLs are checked.

## Output
The output of the program includes:

* Regular logs for every 100 URLs processed. These logs contain the total elapsed time and the average processing speed.
* A comprehensive summary of the errors encountered during the execution.

The results of the check are stored in a SQLite database in a table named url_status. Each entry in the table includes the following fields:

* id (integer): A unique identifier for each entry.
* domain (text): The original domain checked.
* final_domain (text): The final domain after any redirections.
* status (integer): The HTTP status code received.
* status_description (text): The description of the HTTP status code.
* response_time (numeric): The response time of the request.
* title (text): The title of the webpage, if available.
* timestamp (integer): The timestamp, in epoch millis, when the URL was processed.

## Errors
The program keeps track of four types of errors during execution:

* connection_refused: The connection was refused by the server.
* dns_error: There was a DNS resolution issue.
* title_extract_error: The title could not be extracted from the webpage.
* other_errors: Any other errors encountered during execution.

The error counts are output at the end of the program execution.

## Initialization
At the start of the program, several key components are initialized, such as a logger for logging, a semaphore for controlling concurrent tasks, an HTTP client for making requests, a database connection pool for managing SQLite database connections, and a domain extractor for extracting domains from URLs.

## Processing
The processing of each URL is done in the process_url function. This function:

* Sends a GET request to the URL.
* Extracts important data such as the status, final URL after redirection, and the page title.
* Stores these details in the database.