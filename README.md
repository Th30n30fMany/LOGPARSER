# LogParser

A lightweight, modular log‑analysis tool for DShield honeypots and other security logs.

<p align="center">
<img src="assets/logo_log.png" width="180" alt="LogParser Logo AI Generated :) ">
</p>

LogParser (pronounced like wood log, not system log) is a simple but powerful Python tool for parsing, normalizing, and analyzing logs from HTTP, SSH/Telnet, and Firewall sources. It supports multiple input formats, produces clean metrics, and outputs human‑readable or JSON reports.


## Features

- Multi‑format input support
    
    - CSV
        
    - JSON
        
    - XML
        
    - TAB‑delimited
        
- Multiple log types
    
    - HTTP (404 probes, scanners, crawlers)
        
    - SSH/Telnet (bruteforce attempts)
        
    - Firewall (port scans, blocked traffic)
        
- Unified normalization layer Converts raw logs into a consistent structure regardless of source format.
    
- Metrics engine Counts source IPs, usernames, passwords, ports, user agents, and URL paths.
    
- Flexible output
    
    - Human‑readable text
        
    - JSON
        
- Debug mode Prints normalized entries as they are processed.
    

## Installation

Clone the repository:

Code

```
git clone https://github.com/yourusername/LOGPARSER.git
cd LOGPARSER
```

Create a virtual environment (optional but recommended):

Code

```
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
.\venv\Scripts\Activate.ps1     # Windows PowerShell
```

Install dependencies:

Code

```
pip install -r requirements.txt
```

## Usage

### Basic example

Code

```
python3 LogParser.py \
    --filepath logs/http.csv \
    --file-type CSV \
    --log-type HTTP
```

### Show top 20 results

Code

```
python3 LogParser.py \
    --filepath logs/ssh.json \
    --file-type JSON \
    --log-type SSH \
    --top 20
```

### Output as JSON

Code

```
python3 LogParser.py \
    --filepath logs/firewall.xml \
    --file-type XML \
    --log-type Firewall \
    --output-format json
```

### Debug mode (print normalized entries)

Code

```
python3 LogParser.py --debug ...
```

## How It Works

### 1. Reader Layer

LogParser automatically selects the correct reader based on `--file-type`. Each reader yields raw dictionaries with no validation or type casting.

### 2. Normalization Layer

Raw entries are converted into a unified structure:

Code

```
{
    "timestamp": datetime(...),
    "source_ip": "1.2.3.4",
    "event_type": "SSH",
    "details": {
        "username": "root",
        "password": "123456"
    }
}
```

This ensures the metrics engine always receives predictable data.

### 3. Metrics Engine

Counts meaningful fields using `collections.Counter`:

- IPs
    
- Usernames
    
- Passwords
    
- Ports
    
- User agents
    
- URL paths
    

### 4. Output Layer

Produces either:

- Clean text report
    
- JSON output
    

## Project Structure

Code


```
LOGPARSER/
│
├── LogParser.py            # Main script
├── requirements.txt
├── README.md
│
├── assets/                 # Logos, images, diagrams
│   └── logo.png
│
├── scripts/                # Helper scripts
│   ├── bootstrap.sh
│   └── bootstrap.ps1
│
├── logs/               # Sample logs
│   ├── sample_http.csv
│   ├── sample_ssh.json
│   └── sample_firewall.xml
│
└── tests/                  # Optional unit tests
```

## Bootstrap Script

To help contributors get started quickly, LogParser includes optional bootstrap scripts.

macOS/Linux:

Code

```
./scripts/bootstrap.sh
```

Windows PowerShell:

Code

```
.\scripts\bootstrap.ps1
```

These create a virtual environment and install dependencies automatically.

## Roadmap

Planned enhancements may include:

- GeoIP lookup
    
- Time‑based charts
    
- Filtering by IP, date, or event type
    
- Export to CSV
    
- Multi‑file batch processing
    
- Plugin system for new log types
    

## License

MIT License