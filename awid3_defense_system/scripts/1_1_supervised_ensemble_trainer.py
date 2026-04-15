#!/usr/bin/env python3
"""
self_healing_trainer.py – FINAL VERSION
- Proper train/test split by file
- GPU first, automatic CPU fallback
- Accumulates all training data (no incremental warm‑start)
- Saves production models and metadata
"""

import joblib
import numpy as np
import pandas as pd
import yaml
import json
import gc
import random
import warnings
import time
import psutil
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from lightgbm import LGBMClassifier
from xgboost import XGBClassifier
from sklearn.metrics import f1_score, accuracy_score
from sklearn.utils.class_weight import compute_class_weight

warnings.filterwarnings('ignore')

# ============================================================
# Load configuration
# ============================================================
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
with open(CONFIG_PATH, "r") as f:
    CFG = yaml.safe_load(f)

DATA_DIR = Path(CFG["dataset"]["cleaned_path"])
SCALERS_DIR = Path(CFG["dataset"]["scalers_path"])
MODEL_DIR = Path(CFG["production"]["model_dir"])
MODEL_DIR.mkdir(parents=True, exist_ok=True)

NORMAL_SAMPLE_RATIO = CFG["training"]["normal_sample_ratio"]
TEST_SPLIT_RATIO = 0.2          # 20% of attack files for testing
TEST_SIZE = CFG["training"]["test_set_size"]

# Base parameters from config (copied to avoid mutation)
LGB_BIN_BASE = CFG["training"]["lgb_binary"].copy()
XGB_BIN_BASE = CFG["training"]["xgb_binary"].copy()
LGB_MULTI_PARAMS = CFG["training"]["lgb_multi"].copy()
RF_MULTI_PARAMS = CFG["training"]["rf_multi"].copy()

# Safety defaults for LightGBM (avoid split errors)
LGB_BIN_BASE.setdefault("min_child_samples", 5)
LGB_BIN_BASE.setdefault("min_data_in_leaf", 1)
LGB_BIN_BASE.setdefault("min_gain_to_split", 0.0)
LGB_MULTI_PARAMS.setdefault("min_child_samples", 5)
LGB_MULTI_PARAMS.setdefault("min_data_in_leaf", 1)

# Parallelism (adjust based on your CPU/RAM)
LGB_BIN_BASE["n_jobs"] = 4
XGB_BIN_BASE["n_jobs"] = 4
LGB_MULTI_PARAMS["n_jobs"] = 4
RF_MULTI_PARAMS["n_jobs"] = -1

print("=" * 80)
print("FINAL SELF‑HEALING TRAINING – PROPER TRAIN/TEST SPLIT")
print("=" * 80)

# ============================================================
# Helper functions
# ============================================================
def mem_usage():
    return psutil.Process().memory_info().rss / 1024**3

def train_binary_lightgbm(X, y, use_gpu=True):
    params = LGB_BIN_BASE.copy()
    if use_gpu:
        params["device"] = "gpu"
        params["gpu_device_id"] = 0
        print("   Attempting LightGBM GPU training...")
    else:
        params["device"] = "cpu"
        params.pop("gpu_device_id", None)
        print("   Attempting LightGBM CPU training...")
    model = LGBMClassifier(**params, random_state=42, verbose=-1, class_weight="balanced")
    try:
        model.fit(X, y)
        print("   ✅ LightGBM trained (GPU)" if use_gpu else "   ✅ LightGBM trained (CPU)")
        return model, True
    except Exception as e:
        print(f"   ❌ LightGBM {'GPU' if use_gpu else 'CPU'} failed: {e}")
        if use_gpu:
            print("   Retrying on CPU...")
            return train_binary_lightgbm(X, y, use_gpu=False)
        else:
            return None, False

def train_binary_xgboost(X, y, use_gpu=True):
    params = XGB_BIN_BASE.copy()
    if use_gpu:
        params["tree_method"] = "hist"
        params["device"] = "cuda"
        print("   Attempting XGBoost GPU training...")
    else:
        params["tree_method"] = "hist"
        params["device"] = "cpu"
        print("   Attempting XGBoost CPU training...")
    model = XGBClassifier(**params, random_state=42, use_label_encoder=False, eval_metric='logloss')
    neg = np.sum(y == 0)
    pos = np.sum(y == 1)
    if pos > 0:
        model.set_params(scale_pos_weight=neg / pos)
    try:
        model.fit(X, y)
        print("   ✅ XGBoost trained (GPU)" if use_gpu else "   ✅ XGBoost trained (CPU)")
        return model, True
    except Exception as e:
        print(f"   ❌ XGBoost {'GPU' if use_gpu else 'CPU'} failed: {e}")
        if use_gpu:
            print("   Retrying on CPU...")
            return train_binary_xgboost(X, y, use_gpu=False)
        else:
            return None, False

# ============================================================
# 1. Load preprocessing artifacts
# ============================================================
print("\n[1/6] Loading preprocessing artifacts...")
le = joblib.load(SCALERS_DIR / "label_encoder.pkl")
NORMAL_LABEL = np.where(le.classes_ == 'Normal')[0][0]
scaler = joblib.load(SCALERS_DIR / "scaler.pkl")
with open(SCALERS_DIR / "feature_names.json", "r") as f:
    feature_names = json.load(f)["feature_names"]
print(f"   Features: {len(feature_names)} | Normal label: {NORMAL_LABEL}")

# ============================================================
# 2. Categorise files and split into train/test by FILE
# ============================================================
print("\n[2/6] Analysing cleaned files...")
all_files = sorted(DATA_DIR.rglob("*cleaned*.parquet"))
print(f"   Found {len(all_files)} files")

attack_files = []
normal_files = []
for f in all_files:
    try:
        df = pd.read_parquet(f)
        unique = df['label'].unique()
        if len(unique) > 1 or (len(unique) == 1 and unique[0] != NORMAL_LABEL):
            attack_files.append(f)
        else:
            normal_files.append(f)
        del df
        gc.collect()
    except Exception as e:
        print(f"   Warning: {f.name}: {e}")

print(f"   Attack files: {len(attack_files)} | Normal files: {len(normal_files)}")
if not attack_files:
    print("ERROR: No attack files.")
    exit(1)

# Split attack files into train/test (by file)
random.seed(42)
random.shuffle(attack_files)
n_test = max(1, int(len(attack_files) * TEST_SPLIT_RATIO))
test_attack_files = attack_files[:n_test]
train_attack_files = attack_files[n_test:]

print(f"   Train attack files: {len(train_attack_files)}")
print(f"   Test attack files: {len(test_attack_files)}")

# Sample normal files for training (keep only a fraction)
sampled_normal = random.sample(normal_files, int(len(normal_files) * NORMAL_SAMPLE_RATIO)) if normal_files else []
train_files = train_attack_files + sampled_normal
print(f"   Total training files: {len(train_files)} (attack + {len(sampled_normal)} normal)")

# ============================================================
# 3. Compute class weights from training files only
# ============================================================
print("\n[3/6] Computing class weights (from training files only)...")
all_labels = []
for f in train_files:
    try:
        df = pd.read_parquet(f)
        all_labels.extend(df['label'].values)
        del df
        gc.collect()
    except:
        pass
all_labels = np.array(all_labels)
unique_labels = np.unique(all_labels)
class_weights = compute_class_weight('balanced', classes=unique_labels, y=all_labels)
class_weight_dict = {int(l): float(w) for l, w in zip(unique_labels, class_weights)}
print("   Class weights (higher = rarer):")
for l in sorted(unique_labels):
    name = le.inverse_transform([l])[0]
    print(f"     {name}: {class_weight_dict[l]:.4f}")

normal_w = class_weight_dict.get(NORMAL_LABEL, 1.0)
malware_w = np.mean([class_weight_dict[l] for l in unique_labels if l != NORMAL_LABEL])
binary_class_weight = {0: normal_w, 1: malware_w}
print(f"   Binary weights: Normal={normal_w:.2f}, Malware={malware_w:.2f}")

# ============================================================
# 4. Malware mapping (based on training labels)
# ============================================================
print("\n[4/6] Creating malware label mapping...")
malware_labels = [l for l in unique_labels if l != NORMAL_LABEL]
malware_to_idx = {l: i for i, l in enumerate(malware_labels)}
idx_to_malware = {i: l for i, l in enumerate(malware_labels)}
mapping_info = {
    "malware_to_idx": {int(k): v for k, v in malware_to_idx.items()},
    "idx_to_malware": {int(k): int(v) for k, v in idx_to_malware.items()}
}
with open(MODEL_DIR / "mapping_info.json", "w") as f:
    json.dump(mapping_info, f, indent=2)

# ============================================================
# 5. Create test set from a held‑out attack file (never seen during training)
# ============================================================
print("\n[5/6] Creating test set from a held‑out attack file...")
test_file = test_attack_files[0]   # pick the first held‑out file
df_test = pd.read_parquet(test_file)
test_size = min(TEST_SIZE, len(df_test))
X_test = pd.DataFrame(index=range(test_size))
for col in feature_names:
    X_test[col] = df_test[col].values[:test_size] if col in df_test.columns else -1
X_test_scaled = scaler.transform(X_test)
y_test = df_test['label'].values[:test_size]
print(f"   Test set: {len(X_test_scaled):,} rows from {test_file.name}")
print(f"   Test labels: {np.unique(y_test)}")
del df_test
gc.collect()

# ============================================================
# 6. Accumulate training data from training files ONLY
# ============================================================
print("\n[6/6] Accumulating training data (this may take a while)...")
binary_X, binary_y = [], []
malware_X, malware_y, malware_y_mapped = [], [], []
total_rows = 0
start_time = time.time()

for idx, f in enumerate(train_files):
    try:
        df = pd.read_parquet(f)
    except Exception as e:
        print(f"   Skipping {f.name}: {e}")
        continue

    X = pd.DataFrame(index=range(len(df)))
    for col in feature_names:
        X[col] = df[col].values if col in df.columns else -1
    X_scaled = scaler.transform(X)
    y = df['label'].values

    # Downsample normal rows aggressively
    normal_mask = (y == NORMAL_LABEL)
    attack_mask = ~normal_mask
    if np.any(normal_mask):
        normal_indices = np.where(normal_mask)[0]
        keep_normal = np.random.choice(normal_indices, size=int(len(normal_indices) * NORMAL_SAMPLE_RATIO), replace=False)
        keep_attack = np.where(attack_mask)[0]
        keep = np.concatenate([keep_normal, keep_attack])
        X_scaled = X_scaled[keep]
        y = y[keep]

    binary_X.append(X_scaled)
    binary_y.append(y)
    total_rows += len(y)

    # Collect malware samples for multi‑class
    malware_mask = (y != NORMAL_LABEL)
    if np.any(malware_mask):
        X_mal = X_scaled[malware_mask]
        y_mal = y[malware_mask]
        y_mal_mapped = np.array([malware_to_idx[l] for l in y_mal])
        malware_X.append(X_mal)
        malware_y.append(y_mal)
        malware_y_mapped.append(y_mal_mapped)

    del df, X, X_scaled
    gc.collect()

    if (idx + 1) % 50 == 0:
        print(f"   Processed {idx+1}/{len(train_files)} files, accumulated {total_rows:,} rows | Mem: {mem_usage():.1f} GB")

# Combine binary data
X_bin_all = np.vstack(binary_X)
y_bin_all = (np.concatenate(binary_y) != NORMAL_LABEL).astype(int)
print(f"\n   Total binary data: {X_bin_all.shape[0]:,} rows, positives: {np.sum(y_bin_all):,}")

# ============================================================
# Train binary models (self‑healing)
# ============================================================
print("\n   Training binary models (GPU first, fallback to CPU)...")
lgb_bin, lgb_ok = train_binary_lightgbm(X_bin_all, y_bin_all, use_gpu=True)
xgb_bin, xgb_ok = train_binary_xgboost(X_bin_all, y_bin_all, use_gpu=True)

if not lgb_ok and not xgb_ok:
    raise RuntimeError("Both binary models failed to train. Check your data.")
elif not lgb_ok:
    print("   Using only XGBoost for binary stage.")
elif not xgb_ok:
    print("   Using only LightGBM for binary stage.")

# ============================================================
# Train multi‑class models on malware samples (from training only)
# ============================================================
if malware_X:
    X_mal_all = np.vstack(malware_X)
    y_mal_all = np.concatenate(malware_y)
    y_mal_mapped_all = np.concatenate(malware_y_mapped)
    print(f"\n   Training multi‑class models on {len(X_mal_all):,} malware samples...")
    lgb_multi = LGBMClassifier(**LGB_MULTI_PARAMS, random_state=42, verbose=-1, class_weight='balanced')
    rf_multi = RandomForestClassifier(**RF_MULTI_PARAMS, random_state=42, class_weight='balanced')
    lgb_multi.fit(X_mal_all, y_mal_mapped_all)
    rf_multi.fit(X_mal_all, y_mal_mapped_all)
    print("   Multi‑class models ready")
else:
    raise RuntimeError("ERROR: No malware samples found. Cannot train multi‑class models.")

# ============================================================
# Evaluation on held‑out test file (never seen during training)
# ============================================================
print("\n" + "=" * 50)
print("EVALUATION ON HELD‑OUT TEST FILE")
print("=" * 50)

def predict_ensemble(X):
    preds = []
    if lgb_ok:
        preds.append(lgb_bin.predict(X))
    if xgb_ok:
        preds.append(xgb_bin.predict(X))
    if not preds:
        return np.full(len(X), NORMAL_LABEL, dtype=int)
    preds_stack = np.vstack(preds)
    is_malware = (np.mean(preds_stack, axis=0) >= 0.5).astype(int)
    final = np.full(len(X), NORMAL_LABEL, dtype=int)
    malware_idx = np.where(is_malware)[0]
    if len(malware_idx) > 0:
        X_mal = X[malware_idx]
        p_lgb = lgb_multi.predict(X_mal)
        for i, idx in enumerate(malware_idx):
            final[idx] = idx_to_malware[p_lgb[i]]
    return final

print("Running predictions...")
batch_size = 10000
all_preds = []
for i in range(0, len(X_test_scaled), batch_size):
    batch = X_test_scaled[i:i+batch_size]
    batch_pred = predict_ensemble(batch)
    all_preds.extend(batch_pred)
y_pred = np.array(all_preds)

acc = accuracy_score(y_test, y_pred)
f1_w = f1_score(y_test, y_pred, average='weighted')
f1_m = f1_score(y_test, y_pred, average='macro')

print(f"\n   Accuracy: {acc:.4f}")
print(f"   Weighted F1: {f1_w:.4f}")
print(f"   Macro F1: {f1_m:.4f}")

print("\n   Per‑class breakdown:")
for label in np.unique(y_test):
    idx = np.where(y_test == label)[0]
    if len(idx) > 0:
        correct = np.sum(y_pred[idx] == label)
        pct = correct / len(idx) * 100
        name = le.inverse_transform([label])[0]
        mark = "✅" if pct >= 90 else ("⚠️" if pct >= 70 else "❌")
        print(f"   {mark} {name}: {correct}/{len(idx)} ({pct:.1f}%)")

# ============================================================
# Save final models
# ============================================================
print(f"\n💾 Saving production models to {MODEL_DIR}...")
if lgb_ok:
    joblib.dump(lgb_bin, MODEL_DIR / CFG["production"]["lgb_binary"])
else:
    joblib.dump(rf_multi, MODEL_DIR / CFG["production"]["lgb_binary"])
if xgb_ok:
    joblib.dump(xgb_bin, MODEL_DIR / CFG["production"]["xgb_binary"])
else:
    joblib.dump(rf_multi, MODEL_DIR / CFG["production"]["xgb_binary"])
joblib.dump(lgb_multi, MODEL_DIR / CFG["production"]["lgb_multi"])
joblib.dump(rf_multi, MODEL_DIR / CFG["production"]["rf_multi"])
joblib.dump(scaler, MODEL_DIR / CFG["production"]["scaler"])
joblib.dump(le, MODEL_DIR / CFG["production"]["label_encoder"])

info = {
    "training_date": datetime.now().isoformat(),
    "accuracy": float(acc),
    "f1_weighted": float(f1_w),
    "f1_macro": float(f1_m),
    "normal_label": int(NORMAL_LABEL),
    "train_attack_files": len(train_attack_files),
    "test_attack_files": len(test_attack_files),
    "normal_files_used": len(sampled_normal),
    "total_rows": total_rows,
    "lgb_ok": lgb_ok,
    "xgb_ok": xgb_ok,
    "training_time_min": (time.time() - start_time) / 60
}
with open(MODEL_DIR / CFG["production"]["model_info"], "w") as f:
    json.dump(info, f, indent=2)

print(f"\n✅ TRAINING COMPLETE in {info['training_time_min']:.1f} minutes")
print("=" * 80)