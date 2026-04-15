#!/usr/bin/env python3
"""
Script 5: Verify the entire AWID3 defense system setup.
Checks all files, imports, model validity, and interface detection.
"""

import sys
import json
import importlib
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

PASS = "✅"
FAIL = "❌"
WARN = "⚠️ "

errors   = []
warnings = []


def check(label: str, condition: bool, fail_msg: str = "", warn: bool = False):
    if condition:
        print(f"  {PASS} {label}")
    else:
        sym = WARN if warn else FAIL
        print(f"  {sym} {label}  — {fail_msg}")
        if warn:
            warnings.append(label)
        else:
            errors.append(label)


def section(title: str):
    print(f"\n{'─'*50}")
    print(f"  {title}")
    print(f"{'─'*50}")


def main():
    print("=" * 50)
    print("   AWID3 Defense System — Setup Verification")
    print("=" * 50)

    # ── Python version ─────────────────────────────────────────────────────────
    section("Python")
    major, minor = sys.version_info[:2]
    check(f"Python {major}.{minor}", major == 3 and minor >= 8,
          "Python 3.8+ required")

    # ── Packages ───────────────────────────────────────────────────────────────
    section("Required Packages")
    packages = [
        ("numpy",           "numpy"),
        ("pandas",          "pandas"),
        ("sklearn",         "scikit-learn"),
        ("lightgbm",        "lightgbm"),
        ("optuna",          "optuna"),
        ("onnx",            "onnx"),
        ("onnxruntime",     "onnxruntime"),
        ("pyarrow",         "pyarrow"),
        ("joblib",          "joblib"),
        ("yaml",            "pyyaml"),
        ("tqdm",            "tqdm"),
        ("psutil",          "psutil"),
        ("skl2onnx",        "skl2onnx"),
        ("matplotlib",      "matplotlib"),
        ("seaborn",         "seaborn"),
    ]
    for import_name, pkg_name in packages:
        try:
            importlib.import_module(import_name)
            check(f"{pkg_name}", True)
        except ImportError:
            check(f"{pkg_name}", False, f"pip install {pkg_name}")

    # Scapy is optional (hardware mode only)
    try:
        import scapy
        check("scapy (hardware mode)", True)
    except ImportError:
        check("scapy (hardware mode)", True, "", warn=True)
        print(f"       (optional — only needed for monitor-mode hardware defense)")

    # ── Config ─────────────────────────────────────────────────────────────────
    section("Configuration")
    check("config.yaml exists", Path("config.yaml").exists(), "File missing")

    try:
        import yaml
        with open("config.yaml") as f:
            cfg = yaml.safe_load(f)
        check("config.yaml valid YAML", True)

        dataset_path = Path(cfg["dataset"]["local_path"])
        check(
            f"Dataset path exists ({dataset_path})",
            dataset_path.exists(),
            "Update local_path in config.yaml",
        )
    except Exception as e:
        check("config.yaml parseable", False, str(e))

    # ── Cleaned data ───────────────────────────────────────────────────────────
    section("Cleaned Dataset")
    cleaned_dir = Path("data/cleaned")
    scalers_dir = Path("data/scalers")

    for split in ("train", "val", "test"):
        p = cleaned_dir / f"{split}.parquet"
        if p.exists():
            try:
                import pyarrow.parquet as pq
                meta = pq.read_metadata(p)
                rows = meta.num_rows
                check(f"{split}.parquet  ({rows:,} rows)", True)
            except Exception:
                check(f"{split}.parquet", True)
        else:
            check(f"{split}.parquet", False,
                  "Run: python scripts/2_clean_dataset.py")

    for fname in ("feature_names.json", "standard_scaler.pkl", "label_encoder.pkl"):
        check(f"{fname}", (scalers_dir / fname).exists(),
              "Run: python scripts/2_clean_dataset.py")

    # ── Model files ────────────────────────────────────────────────────────────
    section("Model Files")
    model_pkl  = Path("models/trained_model.pkl")
    model_onnx = Path("models/model.onnx")

    check("trained_model.pkl", model_pkl.exists(),
          "Run: python scripts/3_train_model.py")
    check("model.onnx", model_onnx.exists(),
          "Run: python scripts/4_export_onnx.py")

    if model_onnx.exists():
        try:
            import onnxruntime as ort
            sess = ort.InferenceSession(str(model_onnx), providers=["CPUExecutionProvider"])
            check("ONNX model loads", True)

            # Quick inference test
            n_feat = sess.get_inputs()[0].shape[1]
            x_test = [[0.0] * n_feat]
            import numpy as np
            x_arr = np.array(x_test, dtype=np.float32)
            out = sess.run(None, {sess.get_inputs()[0].name: x_arr})
            check("ONNX inference works", len(out) > 0)
        except Exception as e:
            check("ONNX model loads", False, str(e))

    # ── Network interface ──────────────────────────────────────────────────────
    section("Network Interface")
    try:
        from src.utils.capability_check import detect_capabilities
        caps = detect_capabilities()
        check(f"Interface found: {caps['interface']}", caps["interface"] != "none",
              "No wireless interface detected")
        check(f"OS: {caps['os']}", True)
        check(f"Recommended mode: {caps['recommended_mode']}", True)

        if caps["monitor_mode"]:
            check("Monitor mode: SUPPORTED", True)
        else:
            check("Monitor mode: Not supported (software mode will be used)",
                  True, "", warn=True)

    except Exception as e:
        check("Capability detection", False, str(e))

    # ── Summary ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 50)
    if not errors:
        if warnings:
            print(f"⚠️   Setup complete with {len(warnings)} warning(s)")
            for w in warnings:
                print(f"     - {w}")
        else:
            print("✅  All checks passed! System is ready.")
        print("\nRun the defense system:")
        print("   python run.py")
    else:
        print(f"❌  {len(errors)} check(s) failed:")
        for e in errors:
            print(f"     - {e}")
        print("\nFix the above issues and re-run this script.")
        sys.exit(1)
    print("=" * 50)


if __name__ == "__main__":
    main()
