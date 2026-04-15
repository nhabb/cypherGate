#!/usr/bin/env python3
"""
SAFE Continuous Training - Batch by batch, never crashes
Run overnight: python safe_train.py
"""

import json
import time
import argparse
from pathlib import Path
import pandas as pd
import numpy as np
import yaml
import joblib
import gc
from lightgbm import LGBMClassifier

with open("config.yaml") as f:
    CFG = yaml.safe_load(f)

CLEANED_DIR = Path(CFG["dataset"]["cleaned_dir"])
SCALERS_DIR = Path(CFG["dataset"]["scalers_dir"])
MODEL_DIR = Path(CFG["model"]["output_dir"])
RANDOM_STATE = CFG["dataset"]["random_state"]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--n-estimators", type=int, default=50, help="Trees per batch")
    parser.add_argument("--batch-size", type=int, default=20, help="Files per batch")
    args = parser.parse_args()
    
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    
    print("=" * 60)
    print("   SAFE CONTINUOUS TRAINING")
    print("   Processes 20 files at a time - WON'T CRASH")
    print("=" * 60)
    
    # Load preprocessing
    scaler = joblib.load(SCALERS_DIR / "scaler.pkl")
    le = joblib.load(SCALERS_DIR / "label_encoder.pkl")
    with open(SCALERS_DIR / "feature_names.json") as f:
        feature_names = json.load(f)["feature_names"]
    
    # Find all files
    files = sorted(CLEANED_DIR.rglob("*cleaned*.parquet"))
    print(f"Found {len(files)} files")
    
    # Load or create model
    model_path = MODEL_DIR / "safe_model.pkl"
    if args.resume and model_path.exists():
        model = joblib.load(model_path)
        print("✅ Resumed existing model")
    else:
        model = LGBMClassifier(
            n_estimators=args.n_estimators,
            num_leaves=64,
            learning_rate=0.05,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            verbose=-1,
            warm_start=True
        )
        print("✅ Created new model")
    
    print(f"Features: {len(feature_names)}")
    print(f"Classes: {len(le.classes_)}")
    print("\nProcessing files in batches...\n")
    
    total_rows = 0
    trained_rows = 0
    model_fitted = False
    batch_num = 0
    
    try:
        # Process files in small batches
        for i in range(0, len(files), args.batch_size):
            batch_num += 1
            batch_files = files[i:i+args.batch_size]
            
            print(f"\n[Batch {batch_num}] Files {i+1}-{min(i+args.batch_size, len(files))}/{len(files)}")
            
            # Load this batch only
            batch_dfs = []
            for f in batch_files:
                df = pd.read_parquet(f)
                batch_dfs.append(df)
            
            batch_df = pd.concat(batch_dfs, ignore_index=True)
            
            # Get labels
            label_col = 'label' if 'label' in batch_df.columns else batch_df.columns[-1]
            y = batch_df[label_col].values
            total_rows += len(batch_df)
            
            # Prepare features
            X = pd.DataFrame(index=range(len(batch_df)))
            for col in feature_names:
                if col in batch_df.columns:
                    X[col] = batch_df[col].values
                else:
                    X[col] = -1
            
            X_scaled = scaler.transform(X)
            
            # Check if multi-class
            unique_classes = np.unique(y)
            
            if len(unique_classes) > 1:
                if not model_fitted:
                    model.fit(X_scaled, y)
                    model_fitted = True
                else:
                    current_estimators = model.n_estimators_
                    model.set_params(n_estimators=current_estimators + args.n_estimators)
                    model.fit(X_scaled, y, init_model=model)
                
                trained_rows += len(batch_df)
                print(f"  ✓ Trained: {len(batch_df):,} rows (total trained: {trained_rows:,})")
            else:
                print(f"  ⊙ Skipped: {len(batch_df):,} rows (single class)")
            
            # Clear memory
            del batch_dfs, batch_df, X, X_scaled
            gc.collect()
            
            # Save checkpoint every 5 batches
            if batch_num % 5 == 0 and model_fitted:
                joblib.dump(model, model_path)
                print(f"  💾 Checkpoint saved")
            
            # Show progress
            elapsed = time.time() - start_time if 'start_time' in dir() else 0
            print(f"  📊 Total: {total_rows:,} rows | Trained: {trained_rows:,} | Trees: {model.n_estimators_}")
        
        print("\n" + "=" * 60)
        print("✅ COMPLETE! All files processed.")
        print(f"   Total rows: {total_rows:,}")
        print(f"   Trained rows: {trained_rows:,}")
        print(f"   Trees: {model.n_estimators_}")
        
        # Save final model
        joblib.dump(model, MODEL_DIR / "trained_model.pkl")
        joblib.dump(scaler, MODEL_DIR / "scaler.pkl")
        joblib.dump(le, MODEL_DIR / "label_encoder.pkl")
        print(f"✅ Model saved to: {MODEL_DIR / 'trained_model.pkl'}")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Stopped by user")
        if model_fitted:
            joblib.dump(model, model_path)
            print(f"✅ Checkpoint saved. Resume with --resume")
        print("=" * 60)

if __name__ == "__main__":
    start_time = time.time()
    main()