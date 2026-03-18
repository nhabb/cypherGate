# Intrusion Detection System using ModernBERT

## Overview

This project implements an Intrusion Detection System (IDS) using a transformer-based model to classify network logs and identify suspicious activity.

The system processes raw `.txt` log files, analyzes each line individually, and outputs structured predictions into a CSV file. It is designed to handle long log entries and detect multiple types of network attacks.


## Model

* Model Name: `ccaug/modernbert-IDS`
* Source: Hugging Face
* Link: [https://huggingface.co/ccaug/modernbert-IDS/tree/main]


## Classes
The model predicts the following 9 classes:

ID  Label    
0   BENIGN  
1   DDoS    
2   LDAP    
3   NetBIOS 
4   MSSQL   
5   Portmap 
6   UDP     
7   SSL     
8   Other   

## Important Notes About the Model

* The model weights are stored in `.safetensors` format.
* The checkpoint uses a `bert.` prefix for encoder weights, while the script expects `encoder.`.
* A key renaming step is applied during loading:
  * `bert.*` → `encoder.*`
* The classifier head is custom-defined in this script and differs from the original Hugging Face implementation.

## Paths and Configuration

Paths are defined relative to the script location:

* `MODEL_DIR`: Location of the model files
* `INPUT_DIR`: Directory containing `.txt` log files
* `RESULTS_CSV`: Output file for predictions

The script automatically scans all `.txt` files in the input directory.

## Model Definition

The model is implemented using PyTorch:

* Encoder: Pre-trained ModernBERT
* Classification head:
  * Linear layer (hidden_size → 512)
  * Layer normalization + ReLU
  * Linear layer (512 → 256)
  * Layer normalization + ReLU
  * Final linear layer (256 → 9 classes)

The `[CLS]` token representation is used for classification.


## Model Loading and Tokenization

### Model Loading

The loading process includes:

1. Loading tokenizer from the local model directory
2. Initializing the custom model
3. Loading `.safetensors` weights
4. Fixing incompatible parameter names
5. Loading weights with `strict=False`
6. Moving model to GPU (if available) or CPU
7. Setting the model to evaluation mode


### Sliding Window Tokenization

To handle long log entries exceeding 512 tokens, the script uses a sliding window approach:

* Maximum length: 512 tokens
* Stride: 128 tokens

Steps:

* Tokenize full text without truncation
* Split into overlapping chunks
* Pad shorter chunks
* Process each chunk independently

This ensures that long inputs are fully analyzed without losing information.


## Classification

### Single Line Classification

For each line:

1. Apply sliding window tokenization
2. Pass each window through the model
3. Sum logits across all windows
4. Apply softmax to compute probabilities
5. Select the predicted class using argmax

The output includes:

* Class ID
* Human-readable label


### File Processing

The script processes all `.txt` files in the input directory:

1. Reads each file
2. Removes empty lines
3. Classifies each line
4. Writes results to a CSV file

Output format:
file  line  class_id  label 


## Suspicious Activity Detection

Any prediction that is not `BENIGN` is flagged during execution:

[!] Line X: <Attack Type>

This allows quick identification of potential threats in network logs.


## Usage

### Requirements

* Python 3.9+
* PyTorch
* transformers
* safetensors

## Input

Place log files in: `outputTXT/`
Each file should contain one log entry per line.

## Output
Results are saved to: `results.csv`
The file contains classification results for all processed logs.