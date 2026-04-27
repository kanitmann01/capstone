"""Render benchmark plots from the summary JSON.

Emits five PNGs into ``docs/benchmark/plots/``:
  - metrics_bar.png
  - day_zero.png
  - bank_recall.png
  - latency.png
  - capability_heatmap.png

Usage:
    python scripts/render_benchmark_plots.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


SUMMARY_PATH = Path("docs/benchmark/benchmark_summary.json")
PLOT_DIR = Path("docs/benchmark/plots")
LENS_ORDER = [
    "heuristics_only",
    "netstar_lookup",
    "hf_url_classifier",
    "gsb_lookup",
    "brand_guard",
]
LENS_LABELS = {
    "heuristics_only": "Heuristics",
    "netstar_lookup": "Netstar",
    "hf_url_classifier": "HF BERT",
    "gsb_lookup": "GSB",
    "brand_guard": "Brand Guard",
}
COLORS = {
    "heuristics_only": "#94a3b8",
    "netstar_lookup": "#60a5fa",
    "hf_url_classifier": "#fbbf24",
    "gsb_lookup": "#a78bfa",
    "brand_guard": "#34d399",
}


def load_summary() -> dict[str, Any]:
    with SUMMARY_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def plot_metrics_bar(summary: dict[str, Any]) -> None:
    lenses = [l for l in LENS_ORDER if l in summary["lenses"]]
    labels = [LENS_LABELS[l] for l in lenses]
    metrics = ["accuracy", "precision", "recall", "f1"]
    x = np.arange(len(lenses))
    width = 0.2

    fig, ax = plt.subplots(figsize=(10, 6))
    for i, metric in enumerate(metrics):
        values = [summary["lenses"][l][metric] for l in lenses]
        ax.bar(
            x + i * width - 1.5 * width,
            values,
            width,
            label=metric.capitalize(),
            alpha=0.85,
        )

    ax.set_ylabel("Score")
    ax.set_title("Benchmark Metrics by Lens")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    ax.set_ylim(0, 1.1)
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(PLOT_DIR / "metrics_bar.png", dpi=150)
    plt.close(fig)


def plot_day_zero(summary: dict[str, Any]) -> None:
    lenses = [l for l in LENS_ORDER if l in summary["lenses"]]
    labels = [LENS_LABELS[l] for l in lenses]
    values = [summary["lenses"][l].get("day_zero_recall", 0) for l in lenses]
    colors = [COLORS[l] for l in lenses]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, values, color=colors, alpha=0.9)
    ax.set_ylabel("Day-Zero Recall")
    ax.set_title("Day-Zero Recall (URLs Missing from All Feeds)")
    ax.set_ylim(0, 1.1)
    ax.grid(axis="y", alpha=0.3)
    for bar in bars:
        height = bar.get_height()
        ax.annotate(
            f"{height:.2f}",
            xy=(bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=9,
        )
    fig.tight_layout()
    fig.savefig(PLOT_DIR / "day_zero.png", dpi=150)
    plt.close(fig)


def plot_bank_recall(summary: dict[str, Any]) -> None:
    lenses = [l for l in LENS_ORDER if l in summary["lenses"]]
    labels = [LENS_LABELS[l] for l in lenses]
    values = [summary["lenses"][l].get("bank_recall", 0) for l in lenses]
    colors = [COLORS[l] for l in lenses]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, values, color=colors, alpha=0.9)
    ax.set_ylabel("Bank-Impersonation Recall")
    ax.set_title("Bank-Impersonation Recall (Phase 0 Payoff)")
    ax.set_ylim(0, 1.1)
    ax.grid(axis="y", alpha=0.3)
    for bar in bars:
        height = bar.get_height()
        ax.annotate(
            f"{height:.2f}",
            xy=(bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=9,
        )
    fig.tight_layout()
    fig.savefig(PLOT_DIR / "bank_recall.png", dpi=150)
    plt.close(fig)


def plot_latency(summary: dict[str, Any]) -> None:
    lenses = [l for l in LENS_ORDER if l in summary["lenses"]]
    labels = [LENS_LABELS[l] for l in lenses]
    values = [summary["lenses"][l].get("median_latency_ms", 0) for l in lenses]
    colors = [COLORS[l] for l in lenses]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, values, color=colors, alpha=0.9)
    ax.set_ylabel("Median Latency (ms)")
    ax.set_title("Median Scan Latency per Lens")
    ax.set_yscale("log")
    ax.grid(axis="y", alpha=0.3)
    for bar in bars:
        height = bar.get_height()
        ax.annotate(
            f"{height:.0f}",
            xy=(bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=9,
        )
    fig.tight_layout()
    fig.savefig(PLOT_DIR / "latency.png", dpi=150)
    plt.close(fig)


def plot_capability_heatmap(summary: dict[str, Any]) -> None:
    lenses = [l for l in LENS_ORDER if l in summary["lenses"]]
    labels = [LENS_LABELS[l] for l in lenses]
    capabilities = ["explainable", "brand_attribution", "offline_capable"]
    cap_labels = ["Explainable", "Brand Attribution", "Offline Capable"]

    matrix = np.zeros((len(lenses), len(capabilities)))
    for i, lens in enumerate(lenses):
        for j, cap in enumerate(capabilities):
            matrix[i, j] = summary["lenses"][lens].get(cap, 0)

    fig, ax = plt.subplots(figsize=(6, 5))
    im = ax.imshow(matrix.T, cmap="YlGn", aspect="auto", vmin=0, vmax=1)
    ax.set_xticks(np.arange(len(labels)))
    ax.set_yticks(np.arange(len(cap_labels)))
    ax.set_xticklabels(labels)
    ax.set_yticklabels(cap_labels)
    ax.set_title("Capability Matrix")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

    for i in range(len(labels)):
        for j in range(len(cap_labels)):
            text = ax.text(
                i,
                j,
                "✓" if matrix[i, j] > 0 else "✗",
                ha="center",
                va="center",
                color="black" if matrix[i, j] > 0 else "gray",
                fontsize=12,
            )

    fig.colorbar(im, ax=ax, shrink=0.6)
    fig.tight_layout()
    fig.savefig(PLOT_DIR / "capability_heatmap.png", dpi=150)
    plt.close(fig)


def main() -> int:
    PLOT_DIR.mkdir(parents=True, exist_ok=True)
    summary = load_summary()

    plot_metrics_bar(summary)
    plot_day_zero(summary)
    plot_bank_recall(summary)
    plot_latency(summary)
    plot_capability_heatmap(summary)

    print(f"Rendered 5 plots to {PLOT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
