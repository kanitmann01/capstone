from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import csv
import json
from pathlib import Path
from typing import Any

from pipeline.evaluation.compare_models import confusion_counts
from pipeline.evaluation.compare_models import metrics_from_counts
from pipeline.evaluation.rules_baseline import score_rules
from pipeline.extraction.html_parser import extract_page_snapshot
from pipeline.modeling.fasttext_dataset import corpus_dedup_key
from pipeline.modeling.fasttext_dataset import serialize_labeled_snapshot
from pipeline.modeling.fasttext_dataset import serialize_snapshot
from pipeline.modeling.fasttext_train import FastTextTrainingConfig
from pipeline.modeling.fasttext_train import default_training_config
from pipeline.modeling.fasttext_train import train_fasttext_model
from pipeline.modeling.inference import FastTextDetector
from pipeline.shared.config import CapstoneConfig
from scanner.dataset_store import BrandLoginDatasetStore
from scanner.settings import ScannerSettings


class AppService:
    def __init__(self, config: CapstoneConfig | None = None):
        self.config = config or CapstoneConfig.from_env()
        self.scanner_settings = ScannerSettings.from_env()
        self.dataset_store = BrandLoginDatasetStore(self.config.dataset_db_path)
        self.detector = FastTextDetector(self.config.fasttext_model_path, threshold=self.config.fasttext_threshold)
        self.latest_evaluation_report: dict[str, Any] | None = None

    def scan_url(self, raw_url: str) -> dict[str, Any]:
        snapshot = extract_page_snapshot(raw_url, self.scanner_settings)
        rules = score_rules(snapshot)
        text = serialize_snapshot(snapshot)
        fasttext_prediction = self.detector.predict_text(text)
        override_brand = self._official_domain_override(snapshot)
        if fasttext_prediction is None:
            risk_score = float(rules["risk_score"])
            prediction = {
                "status": "unknown",
                "unknown_reason": "model_unavailable",
                "risk_score": 0.0,
                "prediction": "unknown",
                "probability": 0.0,
            }
        else:
            risk_score = float(fasttext_prediction.score)
            prediction = {
                "status": "ok",
                **fasttext_prediction.as_dict(),
            }

        hybrid_score = round((risk_score + float(rules["risk_score"])) / 2, 2)
        override_applied = bool(override_brand)
        final_prediction = prediction.get("label") or prediction.get("prediction") or "unknown"
        final_risk_score = round(risk_score, 2)
        final_hybrid_score = hybrid_score
        override_reason = ""
        if override_applied:
            final_prediction = "clean"
            final_risk_score = 0.0
            final_hybrid_score = 0.0
            override_reason = f"official domain match for {override_brand}"
        result = {
            "url": snapshot["normalized_url"],
            "risk_score": final_risk_score,
            "hybrid_score": final_hybrid_score,
            "prediction": final_prediction,
            "rules": rules,
            "fasttext": prediction,
            "brand_impersonation": snapshot["brand_impersonation"],
            "details": snapshot,
            "contributing_checks": self._contributing_checks(snapshot, rules, prediction),
            "unknown_checks": self._unknown_checks(snapshot, prediction),
            "feed_freshness": self._feed_freshness(),
            "override_applied": override_applied,
            "override_reason": override_reason,
        }
        return result

    def scan_combined(self, raw_url: str) -> dict[str, Any]:
        return self.scan_url(raw_url)

    def _contributing_checks(self, snapshot: dict[str, Any], rules: dict[str, Any], prediction: dict[str, Any]) -> list[str]:
        checks: list[str] = []
        if snapshot.get("free_host"):
            checks.append("free_host")
        if snapshot.get("brand_mismatch"):
            checks.append("brand_mismatch")
        if snapshot.get("login_form_present"):
            checks.append("login_form")
        if snapshot.get("suspicious_phrase_hits"):
            checks.append("suspicious_phrases")
        if float(rules.get("risk_score") or 0) > 0:
            checks.append("rules")
        if prediction and prediction.get("status") == "ok":
            checks.append("fasttext")
        return checks

    def _unknown_checks(self, snapshot: dict[str, Any], prediction: dict[str, Any]) -> list[str]:
        unknown: list[str] = []
        if not snapshot.get("content", {}).get("content_fetched", True):
            unknown.append("content")
        if prediction.get("status") != "ok":
            unknown.append("fasttext")
        return unknown

    def _official_domain_override(self, snapshot: dict[str, Any]) -> str:
        brand_summary = snapshot.get("brand_impersonation") or {}
        candidates = brand_summary.get("brand_candidates") or []
        for candidate in candidates:
            if candidate.get("official_domain_match"):
                return str(candidate.get("brand") or "official_brand")
        return ""

    def _feed_freshness(self) -> dict[str, Any]:
        return {
            "last_refresh_utc": None,
            "refresh_error": None,
            "stale_cache": False,
            "refresh_in_progress": False,
        }

    def dataset_summary(self) -> dict[str, Any]:
        return self.dataset_store.summary()

    def dataset_recent(self, limit: int = 25) -> list[dict[str, Any]]:
        return self.dataset_store.iter_recent(limit=limit)

    def export_fasttext_corpus_from_csv(self, input_csv: str | Path, output_path: str | Path) -> dict[str, Any]:
        input_path = Path(input_csv)
        rows = self._read_labeled_rows(input_path)
        lines: list[str] = []
        seen_rows: set[str] = set()
        unique_rows = 0
        for row in rows:
            snapshot = extract_page_snapshot(row["url"], self.scanner_settings)
            label = "phishing" if row["is_phishing"] else "clean"
            row_key = corpus_dedup_key(snapshot, label)
            if row_key in seen_rows:
                continue
            seen_rows.add(row_key)
            lines.append(serialize_labeled_snapshot(snapshot, label))
            unique_rows += 1
        corpus_path = self.config.fasttext_corpus_path if output_path is None else Path(output_path)
        corpus_path.parent.mkdir(parents=True, exist_ok=True)
        corpus_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return {
            "rows": len(rows),
            "unique_rows": unique_rows,
            "duplicate_rows": max(len(rows) - unique_rows, 0),
            "corpus_path": str(corpus_path),
        }

    def train_fasttext_from_csv(
        self,
        *,
        input_csv: str | Path,
        run_dir: str | Path,
        activate_after_training: bool = True,
    ) -> dict[str, Any]:
        input_path = Path(input_csv)
        run_path = Path(run_dir)
        run_path.mkdir(parents=True, exist_ok=True)
        rows = self._read_labeled_rows(input_path)
        feature_rows: list[dict[str, Any]] = []
        corpus_lines: list[str] = []
        seen_rows: set[str] = set()
        for row in rows:
            snapshot = extract_page_snapshot(row["url"], self.scanner_settings)
            label = "phishing" if row["is_phishing"] else "clean"
            row_key = corpus_dedup_key(snapshot, label)
            if row_key in seen_rows:
                continue
            seen_rows.add(row_key)
            feature_rows.append(
                {
                    "url": snapshot["normalized_url"],
                    "label": label,
                    "snapshot": snapshot,
                }
            )
            corpus_lines.append(serialize_labeled_snapshot(snapshot, label))

        corpus_path = run_path / "fasttext_corpus.txt"
        corpus_path.write_text("\n".join(corpus_lines) + ("\n" if corpus_lines else ""), encoding="utf-8")
        train_config = default_training_config(self.config)
        metadata = train_fasttext_model(
            corpus_path=corpus_path,
            model_path=run_path / "brand_login.bin",
            metadata_path=run_path / "brand_login.json",
            config=train_config,
        )
        if activate_after_training:
            self.config.fasttext_model_path.parent.mkdir(parents=True, exist_ok=True)
            self.config.fasttext_metadata_path.parent.mkdir(parents=True, exist_ok=True)
            self.config.fasttext_model_path.write_bytes((run_path / "brand_login.bin").read_bytes())
            self.config.fasttext_metadata_path.write_text((run_path / "brand_login.json").read_text(encoding="utf-8"), encoding="utf-8")
            self.detector = FastTextDetector(self.config.fasttext_model_path, threshold=self.config.fasttext_threshold)

        counts = self._compute_label_counts(feature_rows)
        return {
            "summary": {
                "created_at": utc_now_iso(),
                "completed_at": utc_now_iso(),
                "input_rows": len(rows),
                "usable_rows": len(feature_rows),
                "duplicate_rows": max(len(rows) - len(feature_rows), 0),
                "positive_rows": counts["phishing"],
                "negative_rows": counts["clean"],
                "model_type": "fasttext",
                "model_version": metadata["model_version"],
                "feature_version": metadata["feature_version"],
                "activated": bool(activate_after_training),
            },
            "artifacts": {
                "corpus_path": str(corpus_path),
                "model_path": metadata["model_path"],
                "metadata_path": str(self.config.fasttext_metadata_path if activate_after_training else run_path / "brand_login.json"),
            },
            "hyperparameters": metadata["hyperparameters"],
        }

    def evaluate_csv(self, *, input_csv: str | Path, output_csv: str | Path, threshold: float = 50.0) -> dict[str, Any]:
        from pipeline.evaluation.evaluate import evaluate_csv, build_report_payload

        def scorer(url: str, progress_callback=None):
            del progress_callback
            return self.scan_url(url)

        result = evaluate_csv(input_csv=input_csv, output_csv=output_csv, scorer=scorer, threshold=threshold)
        report = build_report_payload(result)
        self.latest_evaluation_report = report
        return report

    def model_overview(self) -> dict[str, Any]:
        available = self.detector.available()
        metadata = {}
        if self.config.fasttext_metadata_path.exists():
            try:
                metadata = json.loads(self.config.fasttext_metadata_path.read_text(encoding="utf-8"))
            except Exception:
                metadata = {}
        return {
            "available": available,
            "model_path": str(self.config.fasttext_model_path),
            "metadata_path": str(self.config.fasttext_metadata_path),
            "metadata": metadata,
            "threshold": self.config.fasttext_threshold,
        }

    def _read_labeled_rows(self, input_path: Path) -> list[dict[str, Any]]:
        with input_path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            rows = []
            for row in reader:
                url = (row.get("url") or "").strip()
                label_value = str(row.get("is_phishing") or "").strip().lower()
                if not url:
                    continue
                rows.append(
                    {
                        "url": url,
                        "is_phishing": label_value in {"1", "true", "t", "yes", "y", "phishing"},
                    }
                )
        return rows

    def _compute_label_counts(self, rows: list[dict[str, Any]]) -> dict[str, int]:
        counts = {"phishing": 0, "clean": 0}
        for row in rows:
            counts[row["label"]] += 1
        return counts


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
