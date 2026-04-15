#!/usr/bin/env python3
"""
check_attacks.py - Check what attack types are in a cleaned parquet file
Shows RAW labels without encoding
"""

import pandas as pd
import sys
from pathlib import Path
from collections import Counter

def check_attacks(file_path):
    """Analyze attack types in a cleaned parquet file"""
    
    if not Path(file_path).exists():
        print(f"❌ File not found: {file_path}")
        return
    
    # Load the file
    df = pd.read_parquet(file_path)
    
    print('=' * 70)
    print(f'FILE: {Path(file_path).name}')
    print('=' * 70)
    print(f'Total rows: {len(df):,}')
    print(f'Total columns: {len(df.columns)}')
    print()
    
    # Check label column
    if 'label' not in df.columns:
        print("❌ No 'label' column found in file!")
        print(f"Available columns: {df.columns[:10].tolist()}...")
        return
    
    # Get RAW label distribution (no encoding)
    label_counts = df['label'].value_counts().sort_index()
    
    print('RAW LABELS IN THIS FILE:')
    print('-' * 40)
    for label, count in label_counts.items():
        percentage = count / len(df) * 100
        print(f'  Label {label}: {count:,} rows ({percentage:.1f}%)')
    
    print()
    print('SAMPLE OF FIRST 20 LABELS:')
    print(df['label'].head(20).tolist())
    print()
    
    # Check what the unique labels are
    unique_labels = df['label'].unique()
    print(f'UNIQUE LABELS: {sorted(unique_labels)}')
    print()
    
    # Check if file contains what it should based on filename
    filename = Path(file_path).stem.lower()
    print('FILENAME ANALYSIS:')
    print('-' * 40)
    
    # Map filename patterns to expected label ranges
    if 'kr00k' in filename:
        print(f'  Expected: Kr00k attack (should NOT be label 0/Normal)')
    elif 'deauth' in filename:
        print(f'  Expected: Deauth attack')
    elif 'botnet' in filename:
        print(f'  Expected: Botnet attack')
    elif 'malware' in filename:
        print(f'  Expected: Malware attack')
    elif 'normal' in filename:
        print(f'  Expected: Normal traffic')
    elif 'flood' in filename:
        print(f'  Expected: Flooding attack')
    elif 'injection' in filename:
        print(f'  Expected: Injection attack')
    elif 'evil' in filename or 'twin' in filename:
        print(f'  Expected: Evil Twin attack')
    elif 'krack' in filename:
        print(f'  Expected: Krack attack')
    elif 'rogue' in filename:
        print(f'  Expected: Rogue AP attack')
    else:
        print(f'  Unknown attack type from filename')
    
    # Check if all labels are 0 (Normal)
    if all(df['label'] == 0):
        print(f'\n  ⚠️ WARNING: All labels are 0 (Normal)!')
        print(f'     This file named "{Path(file_path).name}" contains NO attacks!')
        print(f'     Possible issues:')
        print(f'       1. The original CSV had no attack labels')
        print(f'       2. The cleaning script mislabeled everything as Normal')
        print(f'       3. This is actually a Normal traffic file')
    elif 0 in unique_labels and len(unique_labels) > 1:
        normal_count = (df['label'] == 0).sum()
        print(f'\n  Contains {normal_count} Normal rows and {len(df)-normal_count} attack rows')
    
    print()
    print('=' * 70)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_attacks.py /path/to/file.parquet")
        print("\nExample:")
        print("  python check_attacks.py /run/media/ynohtna2220/SHARED/UNIVERSITY/Year 3/FYP/DATASET/archive/CSV/1.Deauth/Deauth_0(cleaned).parquet")
        sys.exit(1)
    
    check_attacks(sys.argv[1])