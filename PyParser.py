# First run will be in psudo code to outline logic. 

# Frontmatter
#!/usr/bin/env python3

# import libraries 

import argparse
import json 
import csv 
import lxml.etree 
from datetime import datetime 
# import re 
# import datetime
# import ...

"""
PyParser - A simple log parser for HTTP 404 error, SSH/Telnet, and Firewall logs produced by DShield Honeypots

"""
# Program starts here! 

# Global variables and constants 
## Define log entry structure

log_entry = {
    "timestamp" : None,
    "source_ip" : None, 
    "event_type" : None, # HTTP, SSH, Firewall
    "details": {
        "url_path": None, # HTTP specific
        "user_agent": None, # HTTP specific
        "username": None, # SSH specific
        "password": None, # SSH specific
        "source_port": None, # Firewall specific
        "target_port": None, # Firewall specific
        "target_ip": None # Firewall specific
    }
}
# Define supported log types and formats
supported_log_types = ["HTTP", "SSH", "Firewall"]
supported_file_formats = ["JSON", "CSV", "XML", "TAB"]
# Define details structure for each log type
log_details_structure = {
    "HTTP": ["url_path", "user_agent"],
    "SSH": ["username", "password",],
    "Firewall": ["source_port", "target_port", "target_ip"]
}

   
# Combine time and date if not single value. 
def build_timestamp(date_str, time_str):
    combined = f"{date_str} {time_str}"
    formats = [
        "%Y-%m-%d %H:%M:%S"  # full timestamp with seconds
    ]
    for fmt in formats:
        try:
            return datetime.strptime(combined, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized timestamp format: {combined}")





# Define flags and arguments using argparse 
## Input log file type will be required arguments
## JSON, CSV, XML TAB delimited file types 
# HTTP, SSH, Firewall log types
# Optional arguments for output type, output filename. 
## Output default with no flag is console in JSON format. 
## Output default with flag but no type is CSV file. 
## If Filename is not provided, use default naming with timestamp.

# Define functions to read/stream log entries based file type (and size?)
# if file less than certain size, read all at once.
# if file larger than certain size, stream line by line.
## CSV log reader function

## JSON log reader function

## XML log reader function

## TAB delimited log reader function 

# Define function to convert parsed log entries into standardized structure
## Common function to map log details based on log type
def normalize_log_entry(raw_log_data, event_type):

 # Pull date and time column
    timestamp = build_timestamp(raw_log_data.get("date"), raw_log_data.get("time"))

    entry = {
        "timestamp": timestamp,
        "source_ip": raw_data.get("source_ip"),
        "event_type": event_type,
        "details": {}
    }
# Define functions to parse log entries based on log type 

## CSV log parser function

## JSON log parser function

## XML log parser function

## TAB delimited log parser function 


# Define function to output parsed data in desired format (JSON, CSV, TXT)
## Write to file or print to console based on user preference

# Main function to coordinate reading, parsing, and outputting log data
def main():

    # Parse command-line arguments

    # Read log file

    # Parse log entries

    # Output parsed data

    pass  # Placeholder for main function logic

# Call main function when script is executed
main()