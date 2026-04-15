#!/usr/bin/env python3
"""
Script 2: Clean AWID3 dataset - PRESERVES ALL FEATURES
No longer drops high-null columns (keeps wlan.bssid, signal strength, etc.)
"""

import argparse
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import yaml
from pathlib import Path
from tqdm import tqdm
import gc
import warnings
warnings.filterwarnings("ignore")

with open("config.yaml") as f:
    CFG = yaml.safe_load(f)


def clean_single_file(csv_path, scaler, le, feature_cols):
    """Clean a single CSV file and return cleaned dataframe"""
    all_chunks = []
    
    for chunk in pd.read_csv(csv_path, chunksize=10000, low_memory=False):
        label_col = 'Label'
        y = chunk[label_col].astype(str).str.strip()
        y = y.replace({'normal': 'Normal', 'NORMAL': 'Normal'})
        
        X = chunk.drop(columns=[label_col])
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors='coerce')
        X = X.fillna(-1).replace([np.inf, -np.inf], -1)
        
        X_aligned = pd.DataFrame(index=X.index)
        for col in feature_cols:
            if col in X.columns:
                X_aligned[col] = X[col]
            else:
                X_aligned[col] = -1
        
        X_aligned = X_aligned[feature_cols]
        X_scaled = scaler.transform(X_aligned)
        y_encoded = le.transform(y)
        
        df_chunk = pd.DataFrame(X_scaled, columns=feature_cols)
        df_chunk['label'] = y_encoded
        all_chunks.append(df_chunk)
        
        del chunk, X, y, X_aligned, X_scaled, y_encoded
        gc.collect()
    
    if all_chunks:
        return pd.concat(all_chunks, ignore_index=True)
    return None


def find_all_csv_files(root_path):
    """Recursively find all CSV files"""
    csv_files = list(root_path.rglob("*.csv"))
    csv_files.extend(list(root_path.rglob("*.CSV")))
    csv_files = [f for f in csv_files if "(cleaned)" not in f.name]
    return sorted(csv_files)


def get_all_unique_labels(csv_files):
    """Scan ALL files to get EVERY possible label"""
    print("Scanning ALL files for complete label set...")
    all_labels = set()
    
    for filepath in tqdm(csv_files, desc="  Scanning for labels"):
        try:
            for chunk in pd.read_csv(filepath, chunksize=50000, low_memory=False):
                labels = chunk['Label'].astype(str).str.strip()
                labels = labels.replace({'normal': 'Normal', 'NORMAL': 'Normal'})
                all_labels.update(labels.unique())
                break
        except Exception as e:
            print(f"    Warning: Could not scan {filepath.name}: {e}")
            continue
    
    print(f"  Found {len(all_labels)} unique labels: {sorted(all_labels)}")
    return sorted(all_labels)


def get_all_feature_columns(first_file):
    """
    Get ALL feature columns from the first file.
    IMPORTANT: Do NOT drop high-null columns - they are needed for detection!
    """
    print("Getting all feature columns...")
    sample_chunk = next(pd.read_csv(first_file, chunksize=1000, low_memory=False))
    X_sample = sample_chunk.drop(columns=['Label'])
    
    # Convert to numeric
    for col in X_sample.columns:
        X_sample[col] = pd.to_numeric(X_sample[col], errors='coerce')
    
    # ONLY remove constant columns (all same value in every row)
    constant_cols = [col for col in X_sample.columns if X_sample[col].nunique() <= 1]
    if constant_cols:
        print(f"  Dropping {len(constant_cols)} constant columns (all same value)")
        X_sample = X_sample.drop(columns=constant_cols)
    
    # IMPORTANT: Do NOT remove high-null columns!
    # Features like wlan.bssid, radiotap.dbm_antsignal may be null in many rows
    # but are CRITICAL for attack detection and whitelisting
    
    feature_cols = X_sample.columns.tolist()
    print(f"  Selected {len(feature_cols)} features (kept all non-constant columns)")
    
    # Print important features that are present
    important_features = ['wlan.bssid', 'radiotap.dbm_antsignal', 'radiotap.channel.freq', 
                          'wlan.fc.type', 'wlan.fc.subtype', 'frame.len']
    present = [f for f in important_features if f in feature_cols]
    missing = [f for f in important_features if f not in feature_cols]
    if present:
        print(f"  Present important features: {present}")
    if missing:
        print(f"  ⚠️ Missing important features: {missing}")
    
    return feature_cols


def fit_scaler_on_sample(csv_files, feature_cols, sample_rows=200000):
    """Fit scaler using samples from multiple files"""
    print(f"Fitting scaler on ~{sample_rows:,} sample rows...")
    
    samples = []
    rows_collected = 0
    
    for filepath in tqdm(csv_files[:20], desc="  Sampling for scaler"):
        for chunk in pd.read_csv(filepath, chunksize=10000, low_memory=False):
            X = chunk.drop(columns=['Label'])
            for col in X.columns:
                X[col] = pd.to_numeric(X[col], errors='coerce')
            X = X.fillna(-1).replace([np.inf, -np.inf], -1)
            
            available = [c for c in feature_cols if c in X.columns]
            X = X[available]
            samples.append(X)
            rows_collected += len(X)
            
            if rows_collected >= sample_rows:
                break
        if rows_collected >= sample_rows:
            break
    
    sample_df = pd.concat(samples, ignore_index=True)
    print(f"  Sampled {len(sample_df):,} rows with {len(sample_df.columns)} features")
    
    scaler = StandardScaler()
    scaler.fit(sample_df)
    
    return scaler


def main():
    parser = argparse.ArgumentParser(description="Clean AWID3 - Preserves all features")
    parser.add_argument("--dataset-path", type=str, default=None)
    parser.add_argument("--resume", action="store_true", help="Skip already cleaned files")
    args = parser.parse_args()
    
    if args.dataset_path:
        dataset_path = Path(args.dataset_path)
    else:
        dataset_path = Path(CFG["dataset"]["local_path"])
    
    print("=" * 70)
    print("   AWID3 CLEANING - PRESERVES ALL FEATURES")
    print("   (Keeps wlan.bssid, signal strength, etc. for better detection)")
    print("=" * 70)
    print(f"Dataset: {dataset_path}")
    print()
    
    # Find all CSV files
    csv_files = find_all_csv_files(dataset_path)
    if not csv_files:
        print(f"No CSV files found in {dataset_path}")
        return
    
    print(f"Found {len(csv_files)} CSV files to process")
    
    total_size_gb = sum(f.stat().st_size for f in csv_files) / (1024**3)
    avg_size_mb = (total_size_gb * 1024) / len(csv_files) if csv_files else 0
    print(f"Total size: {total_size_gb:.1f} GB")
    print(f"Average file size: {avg_size_mb:.1f} MB")
    print()
    
    # Step 1: Get ALL feature columns (no dropping high-null)
    print("[1/5] Getting all feature columns...")
    feature_cols = get_all_feature_columns(csv_files[0])
    
    # Step 2: Scan ALL files for labels
    print("\n[2/5] Scanning ALL files for complete label set...")
    all_labels = get_all_unique_labels(csv_files)
    
    # Step 3: Fit scaler on sample
    print("\n[3/5] Fitting scaler...")
    scaler = fit_scaler_on_sample(csv_files, feature_cols)
    
    # Step 4: Fit label encoder
    print("\n[4/5] Fitting label encoder...")
    le = LabelEncoder()
    le.fit(all_labels)
    print(f"  Encoder ready with {len(le.classes_)} classes: {list(le.classes_)}")
    
    # Save preprocessing artifacts
    scalers_dir = Path(CFG["dataset"]["scalers_dir"])
    scalers_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, scalers_dir / "scaler.pkl")
    joblib.dump(le, scalers_dir / "label_encoder.pkl")
    
    import json
    with open(scalers_dir / "feature_names.json", "w") as f:
        json.dump({
            "feature_names": feature_cols,
            "n_features": len(feature_cols),
            "classes": list(le.classes_)
        }, f, indent=2)
    
    # Step 5: Process each file
    print("\n[5/5] Processing files one by one...")
    print("=" * 70)
    
    processed = 0
    skipped = 0
    failed = []
    
    for i, csv_path in enumerate(csv_files, 1):
        print(f"\n[{i}/{len(csv_files)}] {csv_path.name}")
        print(f"  Size: {csv_path.stat().st_size / (1024**2):.1f} MB")
        
        if args.resume and (csv_path.parent / f"{csv_path.stem}(cleaned).parquet").exists():
            print(f"  ⊙ Skipped (already cleaned)")
            skipped += 1
            continue
        
        try:
            cleaned_df = clean_single_file(csv_path, scaler, le, feature_cols)
            
            if cleaned_df is not None and len(cleaned_df) > 0:
                new_name = csv_path.stem + "(cleaned).parquet"
                new_path = csv_path.parent / new_name
                
                cleaned_df.to_parquet(new_path, index=False)
                
                old_size_mb = csv_path.stat().st_size / (1024**2)
                new_size_mb = new_path.stat().st_size / (1024**2)
                
                csv_path.unlink()
                
                processed += 1
                print(f"  ✓ Cleaned: {len(cleaned_df):,} rows")
                print(f"    Original: {old_size_mb:.1f} MB → Cleaned: {new_size_mb:.1f} MB")
            else:
                print(f"  ✗ No valid rows, skipping")
                skipped += 1
                
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            failed.append((csv_path.name, str(e)))
            continue
        
        del cleaned_df
        gc.collect()
    
    print("\n" + "=" * 70)
    print("✅ PROCESSING COMPLETE!")
    print(f"   Processed: {processed} files")
    print(f"   Skipped: {skipped} files")
    print(f"   Failed: {len(failed)} files")
    
    if failed:
        print(f"\n   Failed files:")
        for fname, err in failed[:10]:
            print(f"     - {fname}: {err}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()