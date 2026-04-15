"""
Inference-time preprocessor: applies the same scaling pipeline used during training.
"""
from __future__ import annotations


import json
import logging
import numpy as np
import joblib
from pathlib import Path

log = logging.getLogger("awid3.preprocessor")


class InferencePreprocessor:
    """
    Wraps the StandardScaler and LabelEncoder from training.
    Used to transform raw packet features before ONNX inference.
    """

    def __init__(self, scalers_dir: str = "data/scalers"):
        scalers_dir = Path(scalers_dir)

        self.scaler = joblib.load(scalers_dir / "standard_scaler.pkl")
        self.le     = joblib.load(scalers_dir / "label_encoder.pkl")

        with open(scalers_dir / "feature_names.json") as f:
            meta = json.load(f)

        self.feature_names: list[str] = meta["feature_names"]
        self.class_names:   list[str] = meta["class_names"]
        self.n_features:    int       = meta["n_features"]
        self.n_classes:     int       = meta["n_classes"]

        log.info(f"Preprocessor loaded: {self.n_features} features, {self.n_classes} classes")

    def transform(self, raw_features: dict | list | np.ndarray) -> np.ndarray:
        """
        Transform raw features into scaled float32 array for ONNX.

        Args:
            raw_features: dict {feature_name: value}, list of values (in order),
                          or numpy array of shape (n_features,) or (batch, n_features)

        Returns:
            np.ndarray of shape (1, n_features) or (batch, n_features), dtype float32
        """
        if isinstance(raw_features, dict):
            arr = np.array(
                [raw_features.get(name, 0.0) for name in self.feature_names],
                dtype=np.float32,
            ).reshape(1, -1)
        elif isinstance(raw_features, list):
            arr = np.array(raw_features, dtype=np.float32).reshape(1, -1)
        else:
            arr = np.array(raw_features, dtype=np.float32)
            if arr.ndim == 1:
                arr = arr.reshape(1, -1)

        # Validate shape
        if arr.shape[1] != self.n_features:
            # Pad or truncate to expected feature count
            if arr.shape[1] < self.n_features:
                pad = np.zeros((arr.shape[0], self.n_features - arr.shape[1]), dtype=np.float32)
                arr = np.hstack([arr, pad])
            else:
                arr = arr[:, :self.n_features]

        # Handle NaN / Inf
        arr = np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)

        # Scale
        arr_scaled = (arr - self.scaler.mean_) / self.scaler.scale_
        return arr_scaled.astype(np.float32)

    def decode_label(self, encoded: int) -> str:
        """Convert encoded integer label back to class name."""
        return self.le.inverse_transform([encoded])[0]

    def decode_labels(self, encoded: np.ndarray) -> list[str]:
        return list(self.le.inverse_transform(encoded))
