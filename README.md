# Sentinel IP Monitor

Sentinel is a lightweight network-defense tool designed to monitor active connections and cross-reference them against real-time threat intelligence feeds. It demonstrates the integration of **OS-level networking utilities**, **Relational Databases (SQL)**, and **automated threat detection**.

## Key Features
* **Real-time Monitoring:** Leverages Linux `ss` (Socket Statistics) to observe active TCP/UDP connections.
* **Threat Correlation:** Uses an **Inner Join** logic to match remote IPs against a local SQLite database of known malicious actors.
* **Automated Intel:** Periodically updates its threat database from public IoC (Indicator of Compromise) feeds.
* **Structured Logging:** Stores alerts with timestamps and process metadata for incident response review.

## The Tech Stack
* **Language:** Python 3.13.5
* **Data Parsing:** `jc` (JSON Converter) for structured output from CLI tools.
* **Database:** SQLite3 (Serverless relational database).
* **OS:** Linux (Designed for Ubuntu/Debian environments).

## Installation & Usage
1. **Install Dependencies:**
   ```bash
   sudo apt install jc
   ```
## to start monitoring
python3 main.py

## Testing the Detection
To verify that the correlation engine is working correctly, you can perform a manual "Smoke Test":

**Add a Test Case:** Manually insert Google's DNS (8.8.8.8) into your local threat database   
    1) Open the database in your terminal:
        ```bash
        sqlite3 sentinel.db
        ```
    2) Insert the following command to the SQLite3 CLI
        ```sql
        INSERT INTO malicious_ips (ip_address, source) VALUES ('8.8.8.8', 'Manual-Test-Case');
        ```
    3) In a seperate terminal, make connection with Google server:
        ```bash
        ping 8.8.8.8
        ```
    4) Run sentinel:
        ```bash
        python3 main.py
        ```     

## Educational Purpose

This project was built to explore the Blue Team workflow:

    Ingestion (Gathering threat data)

    Observation (Monitoring the system)

    Correlation (Linking the two to find a threat)

## License

This project is for educational purposes. Please use responsibly and only on networks you own or have permission to monitor.
