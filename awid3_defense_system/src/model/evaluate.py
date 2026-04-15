"""
Model evaluation utilities: confusion matrix, per-class F1, ROC-AUC.
"""
from __future__ import annotations


import json
import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    f1_score,
    accuracy_score,
)
from sklearn.preprocessing import label_binarize

log = logging.getLogger(__name__)


def evaluate_model(
    model,
    X_test: np.ndarray,
    y_test: np.ndarray,
    class_names: list[str],
    output_dir: str = "models",
) -> dict:
    """
    Full evaluation suite. Returns metrics dict and saves figures.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 50)
    print("   Model Evaluation (Test Set)")
    print("=" * 50)

    # Predictions
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None

    # ── Basic metrics ──────────────────────────────────────────────────────────
    acc  = accuracy_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    f1_m = f1_score(y_test, y_pred, average="macro",    zero_division=0)

    print(f"  Accuracy        : {acc:.4f}")
    print(f"  F1 (weighted)   : {f1:.4f}")
    print(f"  F1 (macro)      : {f1_m:.4f}")

    # ── AUC ───────────────────────────────────────────────────────────────────
    auc = None
    if y_prob is not None:
        try:
            n_classes = len(class_names)
            if n_classes == 2:
                auc = roc_auc_score(y_test, y_prob[:, 1])
            else:
                y_bin = label_binarize(y_test, classes=list(range(n_classes)))
                auc = roc_auc_score(y_bin, y_prob, multi_class="ovr", average="weighted")
            print(f"  AUC (weighted)  : {auc:.4f}")
        except Exception as e:
            log.warning(f"Could not compute AUC: {e}")

    # ── Per-class report ───────────────────────────────────────────────────────
    report = classification_report(
        y_test, y_pred,
        target_names=class_names,
        zero_division=0,
        output_dict=True,
    )
    print("\n  Per-class F1:")
    for cls_name in class_names:
        if cls_name in report:
            f1_cls = report[cls_name]["f1-score"]
            print(f"    {cls_name:<30} {f1_cls:.4f}")

    # ── Confusion matrix ───────────────────────────────────────────────────────
    cm = confusion_matrix(y_test, y_pred)
    _plot_confusion_matrix(cm, class_names, output_dir / "confusion_matrix.png")
    print(f"\n  Confusion matrix → {output_dir}/confusion_matrix.png")

    # ── Feature importance ────────────────────────────────────────────────────
    feat_imp_path = None
    if hasattr(model, "get_feature_importance"):
        feat_imp = model.get_feature_importance()
        feat_imp_path = str(output_dir / "feature_importance.png")
        _plot_feature_importance(feat_imp, feat_imp_path)
        print(f"  Feature importance → {feat_imp_path}")

    # ── Save JSON report ───────────────────────────────────────────────────────
    metrics = {
        "accuracy": round(acc, 6),
        "f1_weighted": round(f1, 6),
        "f1_macro": round(f1_m, 6),
        "auc_weighted": round(auc, 6) if auc is not None else None,
        "per_class": {
            cls: {
                "precision": round(report[cls]["precision"], 4),
                "recall":    round(report[cls]["recall"], 4),
                "f1":        round(report[cls]["f1-score"], 4),
                "support":   report[cls]["support"],
            }
            for cls in class_names if cls in report
        },
    }

    report_path = output_dir / "evaluation_report.json"
    with open(report_path, "w") as fh:
        json.dump(metrics, fh, indent=2)
    print(f"  Evaluation report → {report_path}")
    print("=" * 50)

    return metrics


def _plot_confusion_matrix(cm: np.ndarray, class_names: list, save_path: str):
    """Plot and save confusion matrix heatmap."""
    # Normalize
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True).clip(1)

    fig_size = max(8, len(class_names))
    fig, ax = plt.subplots(figsize=(fig_size, fig_size))
    sns.heatmap(
        cm_norm,
        annot=len(class_names) <= 20,
        fmt=".2f",
        xticklabels=class_names,
        yticklabels=class_names,
        cmap="Blues",
        ax=ax,
    )
    ax.set_xlabel("Predicted")
    ax.set_ylabel("True")
    ax.set_title("Confusion Matrix (Normalized)")
    plt.tight_layout()
    plt.savefig(save_path, dpi=120)
    plt.close()


def _plot_feature_importance(importances: np.ndarray, save_path: str, top_n: int = 30):
    """Plot top-N feature importances."""
    top_idx = np.argsort(importances)[-top_n:][::-1]
    top_imp = importances[top_idx]

    fig, ax = plt.subplots(figsize=(10, 8))
    ax.barh(range(len(top_imp)), top_imp[::-1], align="center")
    ax.set_yticks(range(len(top_imp)))
    ax.set_yticklabels([f"Feature {i}" for i in top_idx[::-1]])
    ax.set_xlabel("Importance")
    ax.set_title(f"Top {top_n} Feature Importances")
    plt.tight_layout()
    plt.savefig(save_path, dpi=120)
    plt.close()
