"""
Model architecture definitions.
Supports LightGBM (default) and 1D-CNN (PyTorch, optional).
"""
from __future__ import annotations

import logging
from typing import Optional

import numpy as np
import joblib
import lightgbm as lgb

log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
#  LIGHTGBM MODEL WRAPPER
# ══════════════════════════════════════════════════════════════════════════════

class AWID3LightGBM:
    """
    LightGBM classifier for AWID3 attack detection.
    Automatically selects binary vs multiclass objective based on n_classes.
    Wraps lgb.LGBMClassifier with AWID3-specific defaults.
    """

    def __init__(
        self,
        n_classes: int = 16,
        num_leaves: int = 127,
        max_depth: int = -1,
        learning_rate: float = 0.05,
        n_estimators: int = 1000,
        min_child_samples: int = 20,
        subsample: float = 0.8,
        colsample_bytree: float = 0.8,
        reg_alpha: float = 0.1,
        reg_lambda: float = 0.1,
        class_weight: Optional[dict] = None,
        n_jobs: int = -1,
        random_state: int = 42,
        verbose: int = -1,
    ):
        self.n_classes = n_classes

        # Auto-select objective and set num_class for multiclass
        if n_classes == 2:
            objective = "binary"
            extra: dict = {}
        else:
            objective = "multiclass"
            extra = {"num_class": n_classes}

        self.params = dict(
            num_leaves=num_leaves,
            max_depth=max_depth,
            learning_rate=learning_rate,
            n_estimators=n_estimators,
            min_child_samples=min_child_samples,
            subsample=subsample,
            colsample_bytree=colsample_bytree,
            reg_alpha=reg_alpha,
            reg_lambda=reg_lambda,
            class_weight=class_weight,
            n_jobs=n_jobs,
            random_state=random_state,
            verbose=verbose,
            objective=objective,
            boosting_type="gbdt",
            **extra,
        )
        self.model: Optional[lgb.LGBMClassifier] = None

    def build(self) -> lgb.LGBMClassifier:
        self.model = lgb.LGBMClassifier(**self.params)
        return self.model

    def fit(
        self,
        X_train,
        y_train,
        X_val=None,
        y_val=None,
        early_stopping_rounds: int = 50,
        callbacks=None,
    ):
        if self.model is None:
            self.build()

        eval_set = [(X_val, y_val)] if X_val is not None else None
        cb = list(callbacks or [])
        if early_stopping_rounds and eval_set:
            cb.append(lgb.early_stopping(early_stopping_rounds, verbose=False))
            cb.append(lgb.log_evaluation(period=50))

        self.model.fit(
            X_train,
            y_train,
            eval_set=eval_set,
            callbacks=cb if cb else None,
        )
        return self

    def predict(self, X) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X) -> np.ndarray:
        raw = self.model.predict_proba(X)
        # binary LightGBM returns shape (n, 2) already
        return raw

    def get_feature_importance(self) -> np.ndarray:
        return self.model.feature_importances_

    @property
    def n_features_in_(self) -> int:
        return self.model.n_features_in_

    def save(self, path: str):
        joblib.dump(self, path)
        log.info(f"Model saved: {path}")

    @classmethod
    def load(cls, path: str) -> "AWID3LightGBM":
        return joblib.load(path)


# ══════════════════════════════════════════════════════════════════════════════
#  OPTUNA SEARCH SPACE
# ══════════════════════════════════════════════════════════════════════════════

def suggest_lightgbm_params(trial) -> dict:
    """Optuna hyperparameter search space for LightGBM (excludes n_classes)."""
    return {
        "num_leaves":        trial.suggest_int("num_leaves", 63, 255),
        "max_depth":         trial.suggest_int("max_depth", 5, 15),
        "learning_rate":     trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
        "n_estimators":      trial.suggest_int("n_estimators", 300, 1500),
        "min_child_samples": trial.suggest_int("min_child_samples", 10, 50),
        "subsample":         trial.suggest_float("subsample", 0.6, 1.0),
        "colsample_bytree":  trial.suggest_float("colsample_bytree", 0.6, 1.0),
        "reg_alpha":         trial.suggest_float("reg_alpha", 1e-4, 10.0, log=True),
        "reg_lambda":        trial.suggest_float("reg_lambda", 1e-4, 10.0, log=True),
    }
