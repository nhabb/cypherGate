# CypherGate AI SOC Architecture

## Overview

CypherGate is a SOC-style AI pipeline that processes raw network traffic, converts it into NLP-readable behavior descriptions, and classifies it using a BERT-based model.

It is designed as a **linear automated security analysis pipeline**.


## System Architecture Diagram (Logical Flow)

             ┌──────────────────────────────┐
             │      RAW DATASET (CSV)       │
             │  Network Flow Records (Zeek) │
             └──────────────┬───────────────┘
                            │
                            ▼
    ┌──────────────────────────────────────────┐
    │     1. ConvertionScript.py              │
    │  Feature → NLP Sentence Transformation   │
    │                                          │
    │  TCP/UDP, packets, bytes → text logic    │
    └──────────────┬──────────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────────┐
    │     Converted Text Dataset (.txt)        │
    │   "connection behavior descriptions"     │
    └──────────────┬──────────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────────┐
    │     2. Bert-IoT-23.py                    │
    │   BERT-based Traffic Classifier          │
    │                                          │
    │   Input: NLP sentences                   │
    │   Output: Benign / Malicious             │
    └──────────────┬──────────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────────┐
    │     Predictions CSV                      │
    │   Sentence → Label mapping               │
    └──────────────┬──────────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────────┐
    │   3. predictionAccuracy.py               │
    │   Evaluation Engine (SOC Analytics)       │
    │                                          │
    │   - Confusion Matrix                     │
    │   - Accuracy Score                       │
    │   - Precision / Recall / F1              │
    └──────────────┬──────────────────────────┘
                   │
                   ▼
    ┌──────────────────────────────────────────┐
    │         FINAL OUTPUT REPORT              │
    │   Security Model Performance Metrics     │
    └──────────────────────────────────────────┘


## SOC DATA FLOW LOGIC

Raw Network Traffic
↓
Feature Extraction (Flow-level)
↓
Behavioral Text Representation
↓
BERT Classification Engine
↓
Security Labeling (Benign / Malicious)
↓
Threat Evaluation Metrics

## Component Roles (SOC Mapping)

### Data Ingestion Layer
- Input: CSV network dataset
- Role: Raw telemetry ingestion

### Feature Transformation Layer
- Script: `ConvertionScript.py`
- Role:
  - Converts network features → semantic behavior descriptions
  - Simulates SOC analyst reasoning in text form


### Detection / AI Layer
- Script: `Bert-IoT-23.py`
- Role:
  - NLP-based anomaly classification
  - Detects malicious behavioral patterns


### Evaluation Layer
- Script: `predictionAccuracy.py`
- Role:
  - Measures model performance
  - Produces SOC metrics (confusion matrix, F1-score)

## Key Design Principle

> Instead of analyzing raw packets directly, the system transforms network behavior into language and applies NLP-based threat detection.

## How to use
Run the following command: python cypherGate.py <dataset name>
NB: all files and datasets must be in the same directory

## Summary

CypherGate is a hybrid:
- Network Security System
- NLP Classification Pipeline
- SOC Analytics Engine
It converts raw traffic into interpretable intelligence for security analysis.