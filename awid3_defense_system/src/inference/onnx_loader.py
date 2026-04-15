"""
ONNX model loader and inference wrapper.
Handles the onnxmltools LightGBM output format:
  output[0] = label array  (int64, shape [n])
  output[1] = probabilities (list of dicts {class_idx: prob})
"""
from __future__ import annotations

import logging
from typing import Optional, Tuple

import numpy as np
import onnxruntime as ort
from pathlib import Path

log = logging.getLogger("awid3.onnx")


class ONNXInferenceEngine:
    """
    Wraps an ONNX Runtime session for AWID3 attack classification.
    Thread-safe; session is created once and reused.
    """

    def __init__(self, model_path: str = "models/model.onnx"):
        model_path = Path(model_path)
        if not model_path.exists():
            raise FileNotFoundError(
                f"ONNX model not found: {model_path}\n"
                "Run: python scripts/4_export_onnx.py"
            )

        providers = ["CPUExecutionProvider"]
        try:
            if "CUDAExecutionProvider" in ort.get_available_providers():
                providers.insert(0, "CUDAExecutionProvider")
                log.info("GPU (CUDA) provider available — using GPU")
        except Exception:
            pass

        opts = ort.SessionOptions()
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        opts.intra_op_num_threads = 0
        opts.log_severity_level = 3  # suppress onnxmltools shape metadata warnings

        self.session = ort.InferenceSession(
            str(model_path),
            sess_options=opts,
            providers=providers,
        )

        self.input_name = self.session.get_inputs()[0].name
        self._output_names = [o.name for o in self.session.get_outputs()]
        self.n_features: int = self.session.get_inputs()[0].shape[1]

        # onnxmltools LightGBM export produces:
        #   output[0] "label"         → int64 class indices
        #   output[1] "probabilities" → list of dicts {class_idx: prob}
        self._label_idx = 0
        self._prob_idx: Optional[int] = None
        for i, name in enumerate(self._output_names):
            if "prob" in name.lower():
                self._prob_idx = i

        log.info(
            f"ONNX loaded: {model_path.name} | "
            f"features={self.n_features} | "
            f"provider={self.session.get_providers()[0]} | "
            f"outputs={self._output_names}"
        )

    # ── Core inference ─────────────────────────────────────────────────────────

    def _run(self, X: np.ndarray):
        X = np.asarray(X, dtype=np.float32)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        return self.session.run(None, {self.input_name: X})

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return predicted class indices, shape (n,)."""
        outputs = self._run(X)
        return np.asarray(outputs[self._label_idx], dtype=np.int64)

    def predict_proba(self, X: np.ndarray) -> Optional[np.ndarray]:
        """
        Return class probabilities, shape (n, n_classes).
        Converts onnxmltools dict format to float32 ndarray.
        Returns None if probability output unavailable.
        """
        if self._prob_idx is None:
            return None

        outputs = self._run(X)
        raw = outputs[self._prob_idx]

        if isinstance(raw, list) and len(raw) > 0 and isinstance(raw[0], dict):
            proba = np.array(
                [[d[k] for k in sorted(d.keys())] for d in raw],
                dtype=np.float32,
            )
            return proba

        # Already ndarray (some export paths)
        return np.asarray(raw, dtype=np.float32)

    def predict_single(self, x: np.ndarray) -> Tuple[int, float]:
        """Predict a single sample. Returns (class_idx, confidence)."""
        x = np.asarray(x, dtype=np.float32).reshape(1, -1)
        outputs = self._run(x)
        label = int(outputs[self._label_idx][0])

        proba_arr = self.predict_proba(x)
        if proba_arr is not None and proba_arr.shape[1] > label:
            confidence = float(proba_arr[0, label])
        else:
            confidence = 1.0

        return label, confidence
