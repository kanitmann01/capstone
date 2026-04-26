"""Improved-model plot helpers and feature column names.

Used by ``scripts/regen_plots.py`` for v2 ROC regeneration and comparison plots.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scanner.ml_features import FEATURE_FIELDS

ALL_FEATURE_NAMES: list[str] = list(FEATURE_FIELDS)


def save_plots(
    history: Any,
    metrics: dict[str, Any],
    te_probs: Any,
    y_te_np: Any,
    run_dir: Path,
    baseline_metrics: dict[str, Any],
) -> None:
    """Write v2 comparison PNGs under ``run_dir/plots/``."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    from sklearn.metrics import confusion_matrix, roc_curve

    plots_dir = run_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    y = np.asarray(y_te_np).astype(int).ravel()
    p = np.asarray(te_probs, dtype=float).ravel()

    # ROC comparison: baseline diagonal-ish vs improved
    fpr, tpr, _ = roc_curve(y, p)
    fig, ax = plt.subplots(figsize=(5.5, 5))
    ax.plot(fpr, tpr, color="#0ea5e9", lw=2, label=f"TF NN v2 (AUC={metrics.get('roc_auc', 0):.3f})")
    ax.plot([0, 1], [0, 1], color="#94a3b8", ls="--", lw=1.5, label="Random")
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("ROC - improved model (test split)")
    ax.legend(loc="lower right")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_aspect("equal", adjustable="box")
    fig.tight_layout()
    fig.savefig(plots_dir / "roc_comparison.png", dpi=120)
    plt.close(fig)

    # Grouped bar: v1 baseline vs v2
    keys = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    labels = ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC"]
    v1 = [float(baseline_metrics.get(k, 0.0)) for k in keys]
    v2 = [float(metrics.get(k, 0.0)) for k in keys]
    x = np.arange(len(labels))
    w = 0.35
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(x - w / 2, v1, width=w, label="TF NN v1", color="#2563eb")
    ax.bar(x + w / 2, v2, width=w, label="TF NN v2", color="#0ea5e9")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.05)
    ax.legend()
    ax.set_title("Metrics - v1 vs v2 (test split)")
    fig.tight_layout()
    fig.savefig(plots_dir / "metrics_comparison.png", dpi=120)
    plt.close(fig)

    # Confusion matrix for v2 at threshold used in metrics
    thr = float(metrics.get("threshold", 0.5))
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    mat = np.array([[tn, fp], [fn, tp]], dtype=float)
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(mat, cmap="Greens", vmin=0)
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Pred 0", "Pred 1"])
    ax.set_yticklabels(["Actual 0", "Actual 1"])
    for (i, j), v in np.ndenumerate(mat):
        ax.text(j, i, int(v), ha="center", va="center", color="black" if v < mat.max() / 2 else "white", fontsize=12)
    ax.set_title(f"Confusion matrix v2 (thr={thr})")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(plots_dir / "confusion_matrix.png", dpi=120)
    plt.close(fig)
