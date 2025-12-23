# **LOGParser**

A lightweight, modular log‑parsing tool for analyzing HTTP, SSH/Telnet, and Firewall logs produced by DShield honeypots. PyParser reads multiple file formats, normalizes entries into a unified schema, computes metrics, and outputs clean reports.

## **Features**

- **Multi‑format input support**
    
    - CSV
        
    - JSON
        
    - XML
        
    - TAB‑delimited
        
- **Multiple log types**
    
    - HTTP (404 probes, scanners, crawlers)
        
    - SSH/Telnet (bruteforce attempts)
        
    - Firewall (port scans, blocked traffic)
        
- **Unified normalization layer** Converts raw logs into a consistent structure regardless of source format.
    
- **Metrics engine** Counts:
    
    - Source IPs
        
    - Usernames
        
    - Passwords
        
    - Ports
        
    - User agents
        
    - URL paths
        
- **Flexible output**
    
    - Human‑readable text
        
    - JSON
        
- **Debug mode** Print normalized entries as they are processed.
    

## **Installation**

Clone the repository:

bash

```
git clone https://github.com/yourusername/PyParser.git
cd PyParser
```

Run with Python 3:

bash

```
python3 pyparser.py --help
```

## **Usage**

### **Basic example**

bash

```
python3 pyparser.py \
    --filepath logs/http.csv \
    --file-type CSV \
    --log-type HTTP
```

### **Show top 20 results**

bash

```
python3 pyparser.py \
    --filepath logs/ssh.json \
    --file-type JSON \
    --log-type SSH \
    --top 20
```

### **Output as JSON**

bash

```
python3 pyparser.py \
    --filepath logs/firewall.xml \
    --file-type XML \
    --log-type Firewall \
    --output-format json
```

### **Debug mode (print normalized entries)**

bash

```
python3 pyparser.py --debug ...
```

## **How It Works**

### **1. Reader Layer**

PyParser automatically selects the correct reader based on `--file-type`:

- `read_log_csv()`
    
- `read_log_json()`
    
- `read_log_xml()`
    
- `read_log_tab()`
    

Each reader yields **raw dictionaries** with no validation or type casting.

### **2. Normalization Layer**

Raw entries are converted into a unified structure:

python

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

### **3. Metrics Engine**

Counts meaningful fields using `collections.Counter`:

- IPs
    
- Usernames
    
- Passwords
    
- Ports
    
- User agents
    
- URL paths
    

### **4. Output Layer**

Produces either:

- Clean text report
    
- JSON output
    

## **Project Structure**

Code

```
pyparser.py
README.md
logs/
    sample_http.csv
    sample_ssh.json
    sample_firewall.xml
```

## **Planned Enhancements**

- GeoIP lookup
    
- Time‑based charts
    
- Filtering by IP, date, or event type
    
- Export to CSV
    
- Multi‑file batch processing
