"""Offline matplotlib plot helpers for training report artifacts.

Used by ``scripts/regen_plots.py`` to regenerate PNG charts from a saved
``report.json`` without retraining.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def save_plots(report: dict[str, Any], run_dir: Path) -> list[Path]:
    """Write matplotlib PNGs under ``run_dir/plots/`` from a training report dict.

    Returns the list of paths written.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    plots_dir = run_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []

    # --- confusion matrix heatmap ---
    cm = report.get("confusion_matrix") or {}
    tn = int(cm.get("tn", 0))
    fp = int(cm.get("fp", 0))
    fn = int(cm.get("fn", 0))
    tp = int(cm.get("tp", 0))
    mat = np.array([[tn, fp], [fn, tp]], dtype=float)
    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(mat, cmap="Blues", vmin=0)
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Pred 0", "Pred 1"])
    ax.set_yticklabels(["Actual 0", "Actual 1"])
    for (i, j), v in np.ndenumerate(mat):
        ax.text(j, i, int(v), ha="center", va="center", color="black" if v < mat.max() / 2 else "white", fontsize=12)
    ax.set_title("Confusion matrix (test)")
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    p = plots_dir / "confusion_matrix.png"
    fig.savefig(p, dpi=120)
    plt.close(fig)
    saved.append(p)

    # --- feature importance (top 15) ---
    fi = list(report.get("feature_importance") or [])[:15]
    if fi:
        names = [str(x.get("feature", "")) for x in fi][::-1]
        vals = [float(x.get("importance", 0.0)) for x in fi][::-1]
        fig, ax = plt.subplots(figsize=(7, 5))
        ax.barh(names, vals, color="#2563eb")
        ax.set_xlabel("Permutation importance (AUC drop)")
        ax.set_title("Top feature importance")
        fig.tight_layout()
        p = plots_dir / "feature_importance.png"
        fig.savefig(p, dpi=120)
        plt.close(fig)
        saved.append(p)

    # --- probability distribution ---
    bins = report.get("probability_distribution") or []
    if bins:
        labels = [str(b.get("label", "")) for b in bins]
        ph = [int(b.get("phishing", 0)) for b in bins]
        le = [int(b.get("legitimate", 0)) for b in bins]
        x = np.arange(len(labels))
        w = 0.42
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.bar(x - w / 2, ph, width=w, label="Phishing", color="#dc2626", alpha=0.85)
        ax.bar(x + w / 2, le, width=w, label="Legitimate", color="#2563eb", alpha=0.85)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
        ax.set_ylabel("Count")
        ax.legend()
        ax.set_title("Predicted probability bins (test)")
        fig.tight_layout()
        p = plots_dir / "probability_distribution.png"
        fig.savefig(p, dpi=120)
        plt.close(fig)
        saved.append(p)

    # --- training history ---
    hist = report.get("training_history") or {}
    loss = hist.get("loss") or []
    val_loss = hist.get("val_loss") or []
    acc = hist.get("accuracy") or hist.get("binary_accuracy") or []
    val_acc = hist.get("val_accuracy") or hist.get("val_binary_accuracy") or []
    if loss or val_loss:
        fig, axes = plt.subplots(1, 2 if (acc or val_acc) else 1, figsize=(10, 4))
        if not isinstance(axes, np.ndarray):
            axes = np.array([axes])
        ax0 = axes[0]
        epochs = range(1, len(loss) + 1) if loss else range(1, len(val_loss) + 1)
        if loss:
            ax0.plot(list(epochs)[: len(loss)], loss, label="train loss")
        if val_loss:
            ax0.plot(list(epochs)[: len(val_loss)], val_loss, label="val loss")
        ax0.set_xlabel("Epoch")
        ax0.set_ylabel("Loss")
        ax0.legend()
        ax0.set_title("Training loss")
        if len(axes) > 1 and (acc or val_acc):
            ax1 = axes[1]
            if acc:
                ax1.plot(range(1, len(acc) + 1), acc, label="train acc")
            if val_acc:
                ax1.plot(range(1, len(val_acc) + 1), val_acc, label="val acc")
            ax1.set_xlabel("Epoch")
            ax1.set_ylabel("Accuracy")
            ax1.legend()
            ax1.set_title("Training accuracy")
        fig.tight_layout()
        p = plots_dir / "training_history.png"
        fig.savefig(p, dpi=120)
        plt.close(fig)
        saved.append(p)

    return saved
