#!/usr/bin/env python3
"""
Script 4: Export trained LightGBM model to ONNX format.
Uses onnxmltools (the correct converter for LightGBM - skl2onnx does NOT support LightGBM).
Verifies the ONNX model produces identical predictions to the original.
"""
from __future__ import annotations

import sys
import json
import logging
import argparse
import numpy as np
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib
import yaml
import onnxruntime as ort

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("export_onnx")

with open("config.yaml") as f:
    CFG = yaml.safe_load(f)

MODEL_DIR   = Path(CFG["model"]["output_dir"])
SCALERS_DIR = Path(CFG["dataset"]["scalers_dir"])
ONNX_PATH   = Path(CFG["onnx"]["output_path"])


def export_lightgbm_to_onnx(wrapper, n_features: int, onnx_path: Path, opset: int = 12):
    """Convert AWID3LightGBM wrapper to ONNX using onnxmltools."""
    try:
        from onnxmltools.convert import convert_lightgbm
        from onnxmltools.convert.common.data_types import FloatTensorType
    except ImportError:
        log.error("onnxmltools not installed. Run: pip install onnxmltools")
        sys.exit(1)

    lgbm_clf = wrapper.model
    n_cls = getattr(lgbm_clf, "n_classes_", "?")
    log.info(f"Converting LightGBM → ONNX (opset={opset}, features={n_features}, classes={n_cls})")

    initial_types = [("float_input", FloatTensorType([None, n_features]))]
    onnx_model = convert_lightgbm(lgbm_clf, initial_types=initial_types, target_opset=opset)

    onnx_path.parent.mkdir(parents=True, exist_ok=True)
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    size_mb = onnx_path.stat().st_size / (1024 * 1024)
    log.info(f"ONNX model saved: {onnx_path}  ({size_mb:.1f} MB)")


def verify_onnx(onnx_path: Path, wrapper, n_features: int, n_samples: int = 1000) -> float:
    """Verify ONNX label predictions match the original model. Returns match %."""
    log.info(f"Verifying with {n_samples} random samples...")

    _opts = ort.SessionOptions(); _opts.log_severity_level = 3
    sess = ort.InferenceSession(str(onnx_path), sess_options=_opts, providers=["CPUExecutionProvider"])
    input_name  = sess.get_inputs()[0].name
    label_name  = sess.get_outputs()[0].name  # first output = "label"

    rng    = np.random.RandomState(42)
    X_test = rng.randn(n_samples, n_features).astype(np.float32)

    y_orig = wrapper.predict(X_test)
    y_onnx = np.asarray(sess.run([label_name], {input_name: X_test})[0], dtype=np.int64)

    pct = float(np.sum(y_orig == y_onnx)) / n_samples * 100
    if pct >= 99.0:
        log.info(f"✅ Verified: {pct:.1f}% match")
    else:
        log.warning(f"⚠️  Only {pct:.1f}% match — check conversion")
    return pct


def print_onnx_info(onnx_path: Path):
    _opts = ort.SessionOptions(); _opts.log_severity_level = 3
    sess = ort.InferenceSession(str(onnx_path), sess_options=_opts, providers=["CPUExecutionProvider"])
    print("\n  ONNX Model Info:")
    for inp in sess.get_inputs():
        print(f"    Input : {inp.name}  shape={inp.shape}  type={inp.type}")
    for out in sess.get_outputs():
        print(f"    Output: {out.name}  shape={out.shape}  type={out.type}")
    print(f"    Size  : {onnx_path.stat().st_size / 1048576:.1f} MB")


def main():
    parser = argparse.ArgumentParser(description="Export LightGBM model to ONNX")
    parser.add_argument("--verify-samples", type=int, default=1000)
    parser.add_argument("--opset", type=int, default=12,
                        help="ONNX opset (default 12 — max reliably supported by onnxmltools)")
    args = parser.parse_args()

    print("=" * 55)
    print("   ONNX Export — LightGBM → ONNX (via onnxmltools)")
    print("=" * 55)

    model_path = MODEL_DIR / "trained_model.pkl"
    if not model_path.exists():
        print(f"❌ Model not found: {model_path}")
        print("   Run: python scripts/3_train_model.py")
        sys.exit(1)

    with open(SCALERS_DIR / "feature_names.json") as f:
        meta = json.load(f)
    n_features = meta["n_features"]
    n_classes  = meta["n_classes"]

    log.info(f"Loading trained model: {model_path}")
    wrapper = joblib.load(model_path)

    print(f"\n[1/3] Exporting ({n_classes} classes, {n_features} features) → ONNX...")
    export_lightgbm_to_onnx(wrapper, n_features, ONNX_PATH, opset=args.opset)

    print(f"\n[2/3] Verifying ONNX predictions...")
    match_pct = verify_onnx(ONNX_PATH, wrapper, n_features, args.verify_samples)

    print(f"\n[3/3] Model details:")
    print_onnx_info(ONNX_PATH)

    print("\n" + "=" * 55)
    print(f"✅ ONNX export complete!  Match: {match_pct:.1f}%")
    print(f"   Output: {ONNX_PATH}")
    print("\nNext: python scripts/5_verify_setup.py  →  python run.py")
    print("=" * 55)


if __name__ == "__main__":
    main()
