"""Regenerate all training plots with the updated color scheme.

Reads saved artifacts (report.json, model files, feature CSVs) so no
retraining is needed. Run from the repo root:

    .venv/bin/python3 scripts/regen_plots.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


# ── v1 baseline ───────────────────────────────────────────────────────────────

def regen_v1(run_dir: Path) -> None:
    report_path = run_dir / "report.json"
    history_path = run_dir / "training_history.json"
    if not report_path.exists():
        print(f"  [v1] report.json not found in {run_dir} - skipping")
        return

    with report_path.open() as f:
        report = json.load(f)

    # Merge saved training history into report so save_plots can find it
    if history_path.exists():
        with history_path.open() as f:
            report["training_history"] = json.load(f)

    from scripts.train_offline import save_plots
    saved = save_plots(report, run_dir)
    print(f"  [v1] Saved {len(saved)} plots:")
    for p in saved:
        print(f"       {p}")


# ── v2 improved ───────────────────────────────────────────────────────────────

def regen_v2(run_dir: Path) -> None:
    import pandas as pd

    dataset_path = run_dir / "feature_dataset.csv"
    model_path   = run_dir / "model_improved.keras"

    if not dataset_path.exists() or not model_path.exists():
        print(f"  [v2] Missing feature_dataset.csv or model - skipping")
        return

    # Reproduce the exact same split used during training
    from scripts.train_improved import ALL_FEATURE_NAMES
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                                  f1_score, roc_auc_score, confusion_matrix, roc_curve)
    import tensorflow as tf

    df = pd.read_csv(dataset_path)
    X  = df[ALL_FEATURE_NAMES].fillna(0.0).astype("float32")
    y  = df["is_phishing"].astype(int)

    _, X_te, _, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    X_te_np = X_te.to_numpy(dtype="float32")
    y_te_np = y_te.to_numpy()

    model = tf.keras.models.load_model(model_path)
    te_probs = model.predict(X_te_np, verbose=0).reshape(-1)

    # Match capstone training default (see scanner.ml_training.TensorFlowTrainingConfig)
    threshold = 0.5
    te_preds = (te_probs >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_te_np, te_preds, labels=[0, 1]).ravel()

    metrics = {
        "accuracy": round(float(accuracy_score(y_te_np, te_preds)), 4),
        "precision": round(float(precision_score(y_te_np, te_preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y_te_np, te_preds, zero_division=0)), 4),
        "f1": round(float(f1_score(y_te_np, te_preds, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_te_np, te_probs)), 4),
        "threshold": threshold,
        "tp": int(tp),
        "fp": int(fp),
        "fn": int(fn),
        "tn": int(tn),
    }

    # Save ROC curve data for the results page charts
    fpr_arr, tpr_arr, _ = roc_curve(y_te_np, te_probs)
    # Downsample to 200 points so the JSON stays small
    step = max(1, len(fpr_arr) // 200)
    roc_data = {
        "fpr": [round(float(v), 5) for v in fpr_arr[::step]],
        "tpr": [round(float(v), 5) for v in tpr_arr[::step]],
        "auc": metrics["roc_auc"],
    }
    roc_text = json.dumps(roc_data)
    (run_dir / "roc_data.json").write_text(roc_text)
    fallback = ROOT / "data" / "processed" / "roc_v2.json"
    fallback.parent.mkdir(parents=True, exist_ok=True)
    fallback.write_text(roc_text)
    print(f"  [v2] ROC data saved ({len(roc_data['fpr'])} points, AUC={roc_data['auc']})")
    print(f"       Also wrote {fallback}")

    # Fake history object so save_plots can access .history dict
    # (real training history wasn't persisted for this run)
    class _FakeHistory:
        history = {"loss": [], "val_loss": [], "accuracy": [], "val_accuracy": []}

    v1_report_path = ROOT / "models" / "run_20260424_093704" / "report.json"
    v1_test = {}
    if v1_report_path.exists():
        with v1_report_path.open(encoding="utf-8") as handle:
            v1_payload = json.load(handle)
        v1_test = (v1_payload.get("splits") or {}).get("test") or {}
    V1_METRICS = {
        "accuracy": float(v1_test.get("accuracy", 0.0)),
        "precision": float(v1_test.get("precision", 0.0)),
        "recall": float(v1_test.get("recall", 0.0)),
        "f1": float(v1_test.get("f1", 0.0)),
        "roc_auc": float(v1_test.get("roc_auc", 0.0)),
    }

    from scripts.train_improved import save_plots
    save_plots(_FakeHistory(), metrics, te_probs, y_te_np, run_dir, V1_METRICS)
    print(f"  [v2] Plots regenerated in {run_dir / 'plots'}/")
    print(f"       (training_curves skipped - history not persisted for this run)")


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    print("Regenerating v1 plots ...")
    regen_v1(ROOT / "models" / "run_20260424_093704")

    print("\nRegenerating v2 plots ...")
    regen_v2(ROOT / "models" / "improved_run")

    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())