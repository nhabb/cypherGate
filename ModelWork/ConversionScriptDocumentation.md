# Network Dataset to Text Converter for ModernBERT IDS

## Overview

This script converts structured network traffic datasets (CSV format) into natural language text suitable for our transformer-based model ModernBERT.

The goal is to transform numerical and statistical network features into **human-readable sentences**, allowing NLP models to process and classify network behavior effectively.


## Purpose
Traditional IDS datasets contain numerical features that are not directly compatible with language models.

This script:

* Converts tabular network data into descriptive text
* Preserves all feature information in sentence form
* Prepares input data for transformer-based intrusion detection models


## Input and Output

### Input
* CSV files containing network flow data
* Files may or may not include headers
* Each row represents a network flow

### Output
* `.txt` files
* Each line represents one network flow in natural language

Example:
Destination port is 443. Flow duration is 1200 microseconds. Total forward packets: 10. ...

## How It Works
The script processes datasets in several steps:

### 1. Header Detection

The script automatically determines whether a CSV file contains column headers.
* If a header exists:
  * It normalizes column names (lowercase, underscores, cleaned characters)
* If no header:
  * It assigns predefined column names manually
This ensures compatibility across different dataset formats.


### 2. Column Standardization

Column names are cleaned using:

* Lowercasing
* Removing special characters
* Replacing spaces with underscores

This guarantees consistent access to features regardless of dataset formatting.


### 3. Safe Data Extraction

A helper function ensures robustness:
* Missing columns are handled gracefully
* Default value `"N/A"` is used when data is unavailable

This prevents runtime crashes due to inconsistent datasets.

### 4. Row to Text Conversion

Each row is transformed into a structured natural language description.

### Example Transformation

Feature            Value 

destination_port   80    
total_fwd_packets  15    

Becomes:
Destination port is 80. Total forward packets: 15.


### Features Included

The script converts all major network features, including:

* Packet counts and sizes
* Flow duration and rates
* Inter-arrival times (IAT)
* TCP flags (SYN, ACK, etc.)
* Header lengths
* Subflow statistics
* Active and idle times
* Label information


### 5. File Processing

For each CSV file:

1. Load dataset
2. Normalize columns
3. Convert each row into text
4. Save output as `.txt` file

Output file naming:
dataset.csv → dataset_text.txt

## Key Functions

### `has_header(csv_path)`
* Detects whether a CSV file contains a header
* Uses the first cell to determine if it is numeric or text


### `safe_get(row, col)`
* Safely retrieves values from a row
* Returns `"N/A"` if the column is missing

### `row_to_text(row)`
* Core function that converts structured data into natural language
* Ensures consistent formatting across all samples

### `process_dataset_file(csv_path, output_path)`
* Processes a single CSV file
* Handles header detection and conversion

### `process_all_datasets()`
* Iterates over all CSV files in the input directory
* Converts them into text format


## Usage

### Requirements

* Python 3.9+
* pandas

## Important Notes

* Input CSV files must follow the expected feature structure
* Missing or malformed rows are skipped automatically
* Output text is designed specifically for **transformer-based models**
* Label information is preserved in the generated text

## Limitations and Dataset Compatibility

This script is designed specifically for network flow datasets with a predefined structure.

## Supported Data Format

The script works correctly when:

* Input data is in CSV format
* Each row represents a network flow
* Columns match (or are similar to) the expected feature set (e.g., CICIDS-style datasets)

## Limitations

The script does not support arbitrary CSV files

* Datasets with different schemas will result in incomplete or meaningless text output
* Non-network datasets (e.g., financial data, user logs) are not compatible
* Raw packet capture files (.pcap) must be preprocessed before use
* Adapting to New Datasets

To use this script with a different dataset:

* Update COLUMN_NAMES to match the dataset
* Modify row_to_text() to reflect the new features
* Ensure consistent sentence structure for model compatibility

## Integration with IDS Model
This script is designed to be used before the IDS classification pipeline:
CSV Dataset → Text Conversion → ModernBERT IDS Model → Predictions