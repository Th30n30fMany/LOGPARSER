#!/usr/bin/env python3

# import libraries 

import argparse
import chardet
import json 
import csv  
import xml.etree.ElementTree as ET
from datetime import datetime 
# import re 
# import datetime
# import lxml.etree
# import ...

"""
PyParser - A 'simple' log parser for HTTP 404 error, SSH/Telnet, and Firewall logs produced by DShield Honeypots

"""

################# variables and constants ####################
# -------------------------
# LOG STRUCTURE DEFINITIONS
# -------------------------

log_details_structure = {
    "HTTP": ["url_path", "user_agent"],
    "SSH": ["username", "password"],
    "Firewall": ["source_port", "target_port", "target_ip"]
}

supported_log_types = list(log_details_structure.keys())
supported_file_formats = ["JSON", "CSV", "XML", "TAB"]

def create_empty_log_entry(event_type):
    return {
        "timestamp": None,
        "source_ip": None,
        "event_type": event_type,
        "details": {field: None for field in log_details_structure[event_type]}
    }


# Define function to convert parsed log entries into standardized structure
## Common function to map log details based on log type
def normalize_log_entry(raw_log_data, event_type):
    # Create a clean, empty log entry for this event type
    entry = create_empty_log_entry(event_type)

    # Build timestamp
    entry["timestamp"] = build_timestamp(
        raw_log_data.get("date"),
        raw_log_data.get("time")
    )

    # Top-level fields
    entry["source_ip"] = raw_log_data.get("source_ip")

    # Fill event-specific details
    for field in log_details_structure[event_type]:
        entry["details"][field] = raw_log_data.get(field)

    return entry


# Combine time and date if not single value. 
def build_timestamp(date_str, time_str):
    combined = f"{date_str} {time_str}"
    formats = [ 
        "%Y-%m-%d %H:%M:%S", # full timestamp with seconds 
        "%Y-%m-%d %H:%M" # timestamp without seconds 
    ]
    for fmt in formats:
        try:
            return datetime.strptime(combined, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized timestamp format: {combined}")

################# END variables and Constants END ####################

################# Argument Parser ####################
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Parse and analyze log files from multiple formats"
    )

    # Required
    parser.add_argument(
        "--filepath",
        required=True,
        help="Path to the log file to process"
    ) 

    parser.add_argument(
        "--file-type",
        required=True,
        help="Format of the input log file."
    )

    parser.add_argument(
        "--log-type",
        required=True,
        help="Type of log entries contained in file"
    )

    # Optional
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print normalized entries for debugging"
    )

    parser.add_argument(
        "--output-format",
        choices=["text", "json"],
        default="text",
        help="Output format for final report. Text default."
    )

    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top results to display (defult: 10)."
    )
    return parser.parse_args()
################# END Argument Parser END ####################

################# Reader Functions ####################
# Reads file as raw data and checks encoding 
def open_log_file(filepath, mode="r", newline=""):
    """
    Open a file with automatic encoding detection and safe fallbacks.
    Returns a file object ready for reading.
    """

    # Step 1: Read a small chunk to guess encoding
    with open(filepath, "rb") as raw:
        sample = raw.read(4096)  # small, fast, enough for detection

    detected = chardet.detect(sample)
    encoding = detected.get("encoding") or "utf-8"

    try:
        # Step 2: Try detected encoding first
        return open(filepath, mode, newline=newline, encoding=encoding)
    except UnicodeDecodeError:
        # Step 3: Fallback to UTF‑8 with replacement
        return open(filepath, mode, newline=newline, encoding="utf-8", errors="replace")

## CSV log reader function
def read_log_csv(filepath):
    """
    Reads a CSV file and yields as RAW rows in dictionaries.

    - No validation
    - No normalization
    - No type casting
    - No filtering

    Returns:
        List of dictionaries (raw string values)
    """
    with open_log_file(filepath) as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield row

## JSON log reader function
def read_log_json(filepath):
    """
    Reads a JSON file and yields as RAW rows in dictionaries.

    - No validation
    - No normalization
    - No type casting
    - No filtering

    Returns:
        List of dictionaries (raw string values)
    """
    with open_log_file(filepath) as f:
        data = json.load(f)
        # JSON can be a list of Objects, a dict containing a list,
        # a dict contaning nested structure, or a single object
        
        # Is a list of Objects  
        if isinstance(data, list):
            for entry in data:
                yield entry

        # A dict containing a list (common) 
        elif isinstance(data, dict):
            # check for list insided dict. 
            for key, value in data.items(): 
                if isinstance(value, list):
                    for entry in value: 
                        yield entry
                    return
            # if no list found, yield the dict itself
            yield data
        else: 
            # unexpected JSON 
            yield data

## XML log reader function (all vibe coded :p ) 
def read_log_xml(filepath):
    """
    Reads an XML log file and yields raw entries as dictionaries.

    - No validation
    - No normalization
    - No type casting
    - No filtering

    Expected structure:
        <logs>
            <logentry>
                <date>2025-12-14</date>
                <time>16:36:00</time>
                <source_ip>1.2.3.4</source_ip>
                ...
            </logentry>
            ...
        </logs>
    """
    with open_log_file(filepath) as f:
        tree = ET.parse(f)
        root = tree.getroot()

        # Find all <logentry> elements anywhere in the XML
        for item in root.findall(".//logentry"):
            entry = {}

            # Convert each child tag into a dict key
            for child in item:
                entry[child.tag] = child.text

            yield entry

## TAB delimited log reader function 
def read_log_tab(filepath):
    """
    Reads a TAB delimiter file and yields as RAW rows in dictionaries.

    - No validation
    - No normalization
    - No type casting
    - No filtering

    Returns:
        List of dictionaries (raw string values)
    """
    with open_log_file(filepath) as f:
        reader = csv.DictReader(f,delimiter="\t")
        for row in reader:
            yield row

def get_log_reader(file_type):
    '''
    Returns the appropriate log reader function based on file type.

    :param file_type: ["JSON", "CSV", "XML", "TAB"]
    '''
    readers = {
        "CSV": read_log_csv,
        "JSON": read_log_json,
        "XML": read_log_xml,
        "TAB": read_log_tab
    }

    file_type = file_type.upper()

    if file_type not in readers: 
        raise ValueError(f"File type Unsupported: {file_type}")
    
    return readers[file_type]

################# END Reader Functions END ####################


################# Metrics and Parsing ####################

# Define functions to parse log entries based on log type 
# 

## CSV log parser function

## JSON log parser function

## XML log parser function

## TAB delimited log parser function 


# Define function to output parsed data in desired format (JSON, CSV, TXT)
## Write to file or print to console based on user preference

# Main function to coordinate reading, parsing, and outputting log data
def main():
    args = parse_arguments()
    # Select the correct reader based on file type
    reader = get_log_reader(args.file_type)
    # Iterate through raw log entries from the file
    for raw_entry in reader(args.filepath):
        # Normalize each entry into your unified schema
        normalized = normalize_log_entry(raw_entry, args.log_type)
        # Debug Mode
        if args.debug: 
            print(normalized)

        # Send normalized entry to your metrics/processing engine
        process(normalized)

    # Parse log entries

    # Output parsed data
    output_results(top=args.top, format=args.output_format)
    pass  # Placeholder for main function logic

# Call main function when script is executed
main()