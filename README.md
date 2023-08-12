# domain_status
**domain_status** is a Rust-based tool designed for multithreaded checking of URL statuses and redirections. It captures errors, tracks progress, and records results in a SQLite database.

## 🌟 Features

* **Speedy Execution**: Utilizes multithreading to process URLs rapidly.
* **Accurate Monitoring**: Keeps track of various connection and DNS issues.
* **Comprehensive Reports**: Provides regular status updates and a detailed error summary after execution.
* **Data Storage**: Saves results to a SQLite database for easy access and further analysis.
* **Domain Insights**: Extracts domains from URLs and captures critical data like final domain after redirection.

## 🔧 Getting Started

### Building
To get started, first build the project:

    cargo build --release

This creates an executable in the ./target/release/ directory.

### Usage
Run the tool with a list of URLs:

    domain_status urls.txt

## Database Details
The results are stored in the domain_results.db SQLite database, inside a table named `url_status`. Each entry in this table consists of:

| Field                  | Type      | Description                                            |
|------------------------|-----------|--------------------------------------------------------|
| **id**                 | `integer` | A unique identifier.                                   |
| **domain**             | `text`    | The initial domain checked.                            |
| **final_domain**       | `text`    | The domain after potential redirections.               |
| **status**             | `integer` | The HTTP status code.                                  |
| **status_description** | `text`    | A brief description of the status code.                |
| **response_time**      | `numeric` | How long the request took (seconds).                   |
| **title**              | `text`    | The webpage's title, when applicable.                  |
| **timestamp**          | `integer` | When the URL check happened, recorded in epoch millis. |

## 📊 Output
Stay informed with detailed logging:

```plaintext
✔️ domain_status::database [INFO] Database file created successfully.
✔️ domain_status [INFO] Processed 1506 lines in 5.33 seconds (~282.29 lines/sec)
✔️ domain_status [INFO] Processed 1851 lines in 10.32 seconds (~179.39 lines/sec)
✔️ domain_status [INFO] Processed 1856 lines in 15.23 seconds (~121.87 lines/sec)
✔️ domain_status [INFO] Error Counts:
✔️ domain_status [INFO]    HTTP request redirect error: 2
✔️ domain_status [INFO]    HTTP request timeout error: 154
✔️ domain_status [INFO]    HTTP request error: 544
✔️ domain_status [INFO]    Title extract error: 49
✔️ domain_status [INFO]    Process URL timeout: 144
```

## 🚀 Performance & Scalability
Designed with scalability in mind, domain_status ensures smooth operation even with large files. If you encounter system-specific errors related to file limits, check and adjust your system's ulimit settings.
