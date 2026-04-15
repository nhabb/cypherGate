#!/usr/bin/env python3
"""
train_anomaly_detector.py – Train Isolation Forest on Normal traffic only.
Run this after self_healing_trainer.py has completed.
"""

import joblib
import numpy as np
import pandas as pd
import json
import gc
from pathlib import Path
from sklearn.ensemble import IsolationForest

# ============================================================
# Paths (update to match your environment)
# ============================================================
DATA_DIR = Path("/run/media/ynohtna2220/SHARED/UNIVERSITY/Year 3/FYP/DATASET/archive/CSV")
SCALERS_DIR = Path("/run/media/ynohtna2220/SHARED/UNIVERSITY/Year 3/FYP/CYPHERGATE/ML/Mine/awid3_defense_system/scripts/data/scalers")
MODEL_DIR = Path("/run/media/ynohtna2220/SHARED/UNIVERSITY/Year 3/FYP/CYPHERGATE/ML/Mine/THE_MACHINE/PRODUCTION")

# Load scaler and feature names
scaler = joblib.load(SCALERS_DIR / "scaler.pkl")
with open(SCALERS_DIR / "feature_names.json", "r") as f:
    feature_names = json.load(f)["feature_names"]

NORMAL_LABEL = 9   # from your label encoder

# ============================================================
# Collect all Normal-only files
# ============================================================
print("Scanning for Normal-only cleaned files...")
normal_files = []
for f in DATA_DIR.rglob("*cleaned*.parquet"):
    try:
        df = pd.read_parquet(f)
        unique = df['label'].unique()
        if len(unique) == 1 and unique[0] == NORMAL_LABEL:
            normal_files.append(f)
        del df
        gc.collect()
    except Exception as e:
        print(f"Warning: {f.name} – {e}")

print(f"Found {len(normal_files)} Normal-only files.")

# ============================================================
# Collect all Normal rows (with downsampling if too large)
# ============================================================
X_normal = []
total_rows = 0
MAX_NORMAL_SAMPLES = 5_000_000   # adjust based on your RAM

for f in normal_files:
    df = pd.read_parquet(f)
    X = pd.DataFrame(index=range(len(df)))
    for col in feature_names:
        X[col] = df[col].values if col in df.columns else -1
    X_scaled = scaler.transform(X)
    X_normal.append(X_scaled)
    total_rows += len(X_scaled)
    del df, X, X_scaled
    gc.collect()
    if total_rows >= MAX_NORMAL_SAMPLES:
        print(f"Reached {MAX_NORMAL_SAMPLES:,} normal samples, stopping.")
        break

X_normal = np.vstack(X_normal)
print(f"Total Normal samples for training: {len(X_normal):,}")

# ============================================================
# Train Isolation Forest
# ============================================================
print("Training Isolation Forest (this may take a few minutes)...")
iso_forest = IsolationForest(
    n_estimators=100,
    contamination=0.05,          # expected proportion of anomalies in live traffic
    random_state=42,
    n_jobs=-1
)
iso_forest.fit(X_normal)

# ============================================================
# Save the model
# ============================================================
joblib.dump(iso_forest, MODEL_DIR / "isolation_forest.pkl")
print(f"Isolation Forest saved to {MODEL_DIR / 'isolation_forest.pkl'}")