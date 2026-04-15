# train_anomaly_detector.py
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
import json

MODEL_DIR = Path("/run/media/ynohtna2220/SHARED/UNIVERSITY/Year 3/FYP/CYPHERGATE/ML/Mine/THE_MACHINE/PRODUCTION")
DATA_DIR = Path("/run/media/ynohtna2220/SHARED/UNIVERSITY/Year 3/FYP/DATASET/archive/CSV")
SCALERS_DIR = Path("/run/media/ynohtna2220/SHARED/UNIVERSITY/Year 3/FYP/CYPHERGATE/ML/Mine/awid3_defense_system/scripts/data/scalers")

# Load scaler and feature names
scaler = joblib.load(SCALERS_DIR / "scaler.pkl")
with open(SCALERS_DIR / "feature_names.json", "r") as f:
    feature_names = json.load(f)["feature_names"]

# Find all Normal files (100% Normal)
normal_files = []
for f in DATA_DIR.rglob("*cleaned*.parquet"):
    df = pd.read_parquet(f)
    if len(df['label'].unique()) == 1 and df['label'].iloc[0] == 9:
        normal_files.append(f)
    del df

print(f"Found {len(normal_files)} Normal-only files")

# Collect all Normal rows (downsample if too large)
X_normal = []
for f in normal_files:
    df = pd.read_parquet(f)
    X = pd.DataFrame(index=range(len(df)))
    for col in feature_names:
        X[col] = df[col].values if col in df.columns else -1
    X_scaled = scaler.transform(X)
    X_normal.append(X_scaled)
    del df, X, X_scaled

X_normal = np.vstack(X_normal)
print(f"Total Normal samples: {len(X_normal):,}")

# Train Isolation Forest
iso_forest = IsolationForest(
    n_estimators=100,
    contamination=0.05,      # expected proportion of anomalies in live traffic
    random_state=42,
    n_jobs=-1
)
iso_forest.fit(X_normal)

# Save
joblib.dump(iso_forest, MODEL_DIR / "isolation_forest.pkl")
print("Isolation Forest saved to", MODEL_DIR / "isolation_forest.pkl")