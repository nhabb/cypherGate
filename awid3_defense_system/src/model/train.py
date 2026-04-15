"""
Training loop for AWID3 LightGBM model with Optuna hyperparameter tuning.
"""
from __future__ import annotations


import json
import logging
import time
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import joblib
import yaml
import optuna
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedKFold

from src.model.architecture import AWID3LightGBM, suggest_lightgbm_params

log = logging.getLogger(__name__)
optuna.logging.set_verbosity(optuna.logging.WARNING)


def load_split(split: str, cleaned_dir: Path) -> tuple[np.ndarray, np.ndarray]:
    """Load a train/val/test parquet split into X, y arrays."""
    df = pd.read_parquet(cleaned_dir / f"{split}.parquet")
    y = df["label"].values.astype(int)
    X = df.drop(columns=["label"]).values.astype(np.float32)
    return X, y


def train_with_optuna(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    class_weights: dict,
    n_classes: int = 16,
    n_trials: int = 20,
    n_jobs_optuna: int = 1,
) -> tuple[AWID3LightGBM, dict]:
    """
    Run Optuna hyperparameter search, return best model and params.
    Uses X_val/y_val as eval set during each trial.
    """
    print(f"\nStarting hyperparameter optimization ({n_trials} trials)...")

    # Convert class_weights dict to per-sample weights
    sample_weight = np.array([
        class_weights.get(str(int(lbl)), 1.0) for lbl in y_train
    ], dtype=np.float32)

    best_score = {"f1": 0.0}

    def objective(trial):
        params = suggest_lightgbm_params(trial)
        model = AWID3LightGBM(n_classes=n_classes, **params, n_jobs=-1)
        model.build()
        model.fit(X_train, y_train, X_val, y_val, early_stopping_rounds=30)
        y_pred = model.predict(X_val)
        score = f1_score(y_val, y_pred, average="weighted", zero_division=0)

        if score > best_score["f1"]:
            best_score["f1"] = score
            print(f"  [ Trial {trial.number+1:>3} ] F1: {score:.4f}  ← Best")
        else:
            print(f"  [ Trial {trial.number+1:>3} ] F1: {score:.4f}")

        return score

    study = optuna.create_study(direction="maximize",
                                sampler=optuna.samplers.TPESampler(seed=42))
    study.optimize(objective, n_trials=n_trials, n_jobs=n_jobs_optuna)

    best_params = study.best_params
    print(f"\nBest F1: {study.best_value:.4f}")
    print(f"Best params: {json.dumps(best_params, indent=2)}")

    # Re-train final model with best params and more estimators
    best_params["n_estimators"] = 2000  # Allow more trees in final run
    final_model = AWID3LightGBM(n_classes=n_classes, **best_params, n_jobs=-1)
    final_model.build()
    print("\nTraining final model with best parameters...")
    final_model.fit(X_train, y_train, X_val, y_val, early_stopping_rounds=50)

    return final_model, best_params


def train_cross_val(
    X_train: np.ndarray,
    y_train: np.ndarray,
    best_params: dict,
    n_classes: int = 16,
    n_folds: int = 5,
) -> list[float]:
    """Run k-fold cross-validation and return per-fold F1 scores."""
    print(f"\nRunning {n_folds}-fold cross-validation...")
    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
    scores = []

    for fold, (tr_idx, val_idx) in enumerate(skf.split(X_train, y_train), 1):
        X_tr, X_v = X_train[tr_idx], X_train[val_idx]
        y_tr, y_v = y_train[tr_idx], y_train[val_idx]

        params = {**best_params, "n_estimators": 500}
        model = AWID3LightGBM(n_classes=n_classes, **params, n_jobs=-1)
        model.build()
        model.fit(X_tr, y_tr, X_v, y_v, early_stopping_rounds=30)
        y_pred = model.predict(X_v)
        score = f1_score(y_v, y_pred, average="weighted", zero_division=0)
        scores.append(score)
        print(f"  Fold {fold}/{n_folds}: F1 = {score:.4f}")

    mean_f1 = np.mean(scores)
    std_f1  = np.std(scores)
    print(f"  CV F1: {mean_f1:.4f} ± {std_f1:.4f}")
    return scores
