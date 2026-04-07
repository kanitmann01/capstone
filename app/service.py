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
from scanner.dataset_store import SnapshotRecord
from scanner.domain_age import DomainAgeScanner
from scanner.feed_ingest import ThreatFeedCache
from scanner.heuristics import URLHeuristics
from scanner.ml_features import extract_features
from scanner.ml_model import MLScanner
from scanner.normalization import normalize_input_url
from scanner.settings import ScannerSettings
from scanner.ssl_check import SSLValidator
from scanner.threat_intel import ThreatIntelScanner


PIPELINE_VERSION = "unified_pipeline_v1"


class AppService:
    def __init__(self, config: CapstoneConfig | None = None):
        self.config = config or CapstoneConfig.from_env()
        self.scanner_settings = ScannerSettings.from_env()
        self.dataset_store = BrandLoginDatasetStore(self.config.dataset_db_path)
        self.feed_cache = ThreatFeedCache(self.scanner_settings)
        self.detector = FastTextDetector(self.config.fasttext_model_path, threshold=self.config.fasttext_threshold)
        self.structured_ml = MLScanner(self.scanner_settings)
        self.latest_evaluation_report: dict[str, Any] | None = None

    def scan_url(self, raw_url: str, *, persist: bool = True, source: str = "live_scan") -> dict[str, Any]:
        snapshot = extract_page_snapshot(raw_url, self.scanner_settings)
        target = normalize_input_url(raw_url)
        rules = score_rules(snapshot)
        fasttext_prediction = self.detector.predict_text(serialize_snapshot(snapshot))
        legacy_checks = self._run_legacy_checks(target, snapshot)
        structured_ml = self._run_structured_ml(target, legacy_checks)
        scores = self._score_components(rules, fasttext_prediction, legacy_checks, structured_ml)
        verdict = self._build_verdict(scores, rules, fasttext_prediction, structured_ml)
        override_brand = self._official_domain_override(snapshot)
        override_applied = False
        override_reason = ""
        if override_brand:
            override_applied = True
            override_reason = f"official domain match for {override_brand}"
            scores["final"] = 0.0
            verdict = {
                "status": "ok",
                "label": "clean",
                "threshold": float(self.config.final_score_threshold),
                "final_score": 0.0,
                "reason": override_reason,
                "signals": ["official_domain_match"],
            }
        elif snapshot.get("free_host") and snapshot.get("brand_mismatch"):
            override_applied = True
            override_reason = "free host with brand mismatch"
            scores["final"] = 100.0
            verdict = {
                "status": "ok",
                "label": "phishing",
                "threshold": float(self.config.final_score_threshold),
                "final_score": 100.0,
                "reason": override_reason,
                "signals": ["free_host", "brand_mismatch"],
            }

        fasttext_payload = self._fasttext_payload(fasttext_prediction)
        checks = self._build_check_map(snapshot, legacy_checks, rules, fasttext_payload, structured_ml)
        contributing_checks = self._contributing_checks(snapshot, rules, fasttext_payload, legacy_checks, structured_ml)
        unknown_checks = self._unknown_checks(snapshot, fasttext_payload, legacy_checks, structured_ml)

        final_score = float(scores["final"])
        result = {
            "url": snapshot["normalized_url"],
            "risk_score": round(final_score, 2),
            "hybrid_score": round(final_score, 2),
            "prediction": verdict["label"],
            "verdict": verdict,
            "scores": scores,
            "rules": rules,
            "fasttext": fasttext_payload,
            "brand_impersonation": snapshot["brand_impersonation"],
            "details": {
                **snapshot,
                "checks": checks,
                "scores": scores,
                "verdict": verdict,
                "rules": rules,
                "fasttext": fasttext_payload,
            },
            "checks": checks,
            "contributing_checks": contributing_checks,
            "unknown_checks": unknown_checks,
            "feed_freshness": self._feed_freshness(),
            "override_applied": override_applied,
            "override_reason": override_reason,
            "artifacts": {
                "persisted": False,
                "record_id": None,
                "source": source,
                "pipeline_version": PIPELINE_VERSION,
            },
        }

        if persist:
            record_id = self._persist_scan(snapshot=snapshot, result=result, source=source)
            result["artifacts"]["persisted"] = True
            result["artifacts"]["record_id"] = record_id

        return result

    def scan_combined(self, raw_url: str, *, persist: bool = True) -> dict[str, Any]:
        return self.scan_url(raw_url, persist=persist, source="api_scan")

    def _contributing_checks(
        self,
        snapshot: dict[str, Any],
        rules: dict[str, Any],
        prediction: dict[str, Any],
        legacy_checks: dict[str, dict[str, Any]],
        structured_ml: dict[str, Any],
    ) -> list[str]:
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
        if structured_ml.get("status") == "ok" and float(structured_ml.get("risk_score") or 0) > 0:
            checks.append("structured_ml")
        for name, result in legacy_checks.items():
            if result.get("status", "ok") == "ok" and float(result.get("risk_score") or 0) > 0:
                checks.append(name)
        return list(dict.fromkeys(checks))

    def _unknown_checks(
        self,
        snapshot: dict[str, Any],
        prediction: dict[str, Any],
        legacy_checks: dict[str, dict[str, Any]],
        structured_ml: dict[str, Any],
    ) -> list[str]:
        unknown: list[str] = []
        if not snapshot.get("content", {}).get("content_fetched", True):
            unknown.append("content")
        if prediction.get("status") != "ok":
            unknown.append("fasttext")
        if structured_ml.get("status") != "ok":
            unknown.append("structured_ml")
        for name, result in legacy_checks.items():
            if result.get("status", "ok") != "ok":
                unknown.append(name)
        return list(dict.fromkeys(unknown))

    def _run_legacy_checks(self, target, snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
        content = snapshot.get("content") or {}
        return {
            "heuristics": URLHeuristics(target).run_checks(),
            "content": content,
            "ssl": SSLValidator(target, self.scanner_settings).run_checks(),
            "domain_age": DomainAgeScanner(target).run_checks(),
            "threat_intel": ThreatIntelScanner(target, self.feed_cache).run_checks(),
        }

    def _run_structured_ml(self, target, legacy_checks: dict[str, dict[str, Any]]) -> dict[str, Any]:
        try:
            features = extract_features(target, legacy_checks)
            return self.structured_ml.scan(features)
        except Exception as exc:
            return {
                "status": "unknown",
                "unknown_reason": "structured_ml_unavailable",
                "error": str(exc),
                "risk_score": 0.0,
                "prediction": "unknown",
            }

    def _score_components(
        self,
        rules: dict[str, Any],
        fasttext_prediction: Any,
        legacy_checks: dict[str, dict[str, Any]],
        structured_ml: dict[str, Any],
    ) -> dict[str, Any]:
        rules_score = float(rules.get("risk_score") or 0)
        fasttext_score = self._safe_prediction_score(fasttext_prediction)
        legacy_score, legacy_contributing, legacy_unknown = self._weighted_legacy_score(legacy_checks)
        structured_score = float(structured_ml.get("risk_score") or 0) if structured_ml.get("status") == "ok" else None
        component_values = {
            "rules": rules_score,
            "fasttext": fasttext_score,
            "legacy": legacy_score,
            "structured_ml": structured_score,
        }
        numerator = 0.0
        denominator = 0.0
        available_components: list[str] = []
        weights = {
            "rules": 0.35,
            "fasttext": 0.35,
            "legacy": 0.20,
            "structured_ml": 0.10,
        }
        for name, score in component_values.items():
            if score is None:
                continue
            available_components.append(name)
            weight = weights.get(name, 0.0)
            numerator += float(score) * float(weight)
            denominator += float(weight)
        final_score = round(numerator / denominator, 2) if denominator else 0.0
        return {
            "final": final_score,
            "rules": round(rules_score, 2),
            "fasttext": round(float(fasttext_score), 2) if fasttext_score is not None else None,
            "legacy": round(float(legacy_score), 2),
            "structured_ml": round(float(structured_score), 2) if structured_score is not None else None,
            "available_components": available_components,
            "legacy_contributing_checks": legacy_contributing,
            "legacy_unknown_checks": legacy_unknown,
        }

    def _build_verdict(
        self,
        scores: dict[str, Any],
        rules: dict[str, Any],
        fasttext_prediction: Any,
        structured_ml: dict[str, Any],
    ) -> dict[str, Any]:
        signals = list(rules.get("reasons") or [])
        if fasttext_prediction is not None:
            signals.append(f"FastText score {scores['fasttext']:.2f}")
        if structured_ml.get("status") == "ok":
            signals.append(f"Structured ML score {scores['structured_ml']:.2f}")
        if scores.get("legacy_contributing_checks"):
            signals.extend(scores["legacy_contributing_checks"])
        label = "phishing" if float(scores["final"]) >= float(self.config.final_score_threshold) else "clean"
        return {
            "status": "ok" if scores.get("available_components") else "unknown",
            "label": label,
            "threshold": float(self.config.final_score_threshold),
            "final_score": float(scores["final"]),
            "reason": "; ".join(dict.fromkeys(signals[:8])) or "Composite score",
            "signals": list(dict.fromkeys(signals[:12])),
        }

    def _build_check_map(
        self,
        snapshot: dict[str, Any],
        legacy_checks: dict[str, dict[str, Any]],
        rules: dict[str, Any],
        fasttext_prediction: dict[str, Any],
        structured_ml: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        checks = dict(legacy_checks)
        checks["rules"] = rules
        checks["fasttext"] = fasttext_prediction
        checks["structured_ml"] = structured_ml
        checks["brand_impersonation"] = snapshot.get("brand_impersonation") or {}
        return checks

    def _persist_scan(self, *, snapshot: dict[str, Any], result: dict[str, Any], source: str) -> int:
        record = SnapshotRecord.create(
            url=snapshot.get("url") or snapshot.get("normalized_url") or "",
            normalized_url=snapshot.get("normalized_url") or snapshot.get("url") or "",
            host=snapshot.get("host") or "",
            source_feed=source,
            source_label=str(result.get("prediction") or "unknown"),
            source_pipeline="app_service",
            pipeline_version=PIPELINE_VERSION,
            raw_html=snapshot.get("raw_html", ""),
            visible_text=snapshot.get("visible_text", ""),
            page_title=snapshot.get("page_title", ""),
            detected_brand=snapshot.get("detected_brand", ""),
            host_provider=snapshot.get("host_provider", ""),
            risk_score=float(result.get("risk_score") or 0),
            prediction=str(result.get("prediction") or "unknown"),
            extraction={
                "rules": result.get("rules"),
                "scores": result.get("scores"),
                "brand_impersonation": result.get("brand_impersonation"),
                "checks": result.get("checks"),
                "feed_freshness": result.get("feed_freshness"),
                "override_applied": result.get("override_applied"),
                "override_reason": result.get("override_reason"),
            },
            label=1 if result.get("prediction") == "phishing" else 0 if result.get("prediction") == "clean" else None,
            notes=str(result.get("verdict", {}).get("reason") or ""),
        )
        return self.dataset_store.add_snapshot(record)

    def _fasttext_payload(self, fasttext_prediction: Any) -> dict[str, Any]:
        if fasttext_prediction is None:
            return {
                "status": "unknown",
                "unknown_reason": "model_unavailable",
                "risk_score": 0.0,
                "prediction": "unknown",
                "probability": 0.0,
            }
        return {"status": "ok", **fasttext_prediction.as_dict()}

    def _safe_prediction_score(self, fasttext_prediction: Any) -> float | None:
        if fasttext_prediction is None:
            return None
        return float(getattr(fasttext_prediction, "score", 0.0) or 0.0)

    def _weighted_legacy_score(self, legacy_checks: dict[str, dict[str, Any]]) -> tuple[float, list[str], list[str]]:
        weights = {
            "heuristics": self.scanner_settings.weights_heuristics,
            "content": self.scanner_settings.weights_content,
            "ssl": self.scanner_settings.weights_ssl,
            "domain_age": self.scanner_settings.weights_domain_age,
            "threat_intel": self.scanner_settings.weights_threat_intel,
        }
        numerator = 0.0
        denominator = 0.0
        contributing: list[str] = []
        unknown: list[str] = []
        for name, result in legacy_checks.items():
            status = result.get("status", "ok")
            if status != "ok":
                unknown.append(name)
                continue
            weight = float(weights.get(name, 0.0))
            if weight <= 0:
                continue
            numerator += float(result.get("risk_score") or 0) * weight
            denominator += weight
            contributing.append(name)
        if denominator == 0:
            return 0.0, contributing, unknown
        return numerator / denominator, contributing, unknown

    def _official_domain_override(self, snapshot: dict[str, Any]) -> str:
        brand_summary = snapshot.get("brand_impersonation") or {}
        candidates = brand_summary.get("brand_candidates") or []
        for candidate in candidates:
            if candidate.get("official_domain_match"):
                return str(candidate.get("brand") or "official_brand")
        return ""

    def _feed_freshness(self) -> dict[str, Any]:
        metadata = self.feed_cache.metadata()
        return {
            "last_refresh_utc": metadata.get("last_refresh_utc"),
            "refresh_error": metadata.get("refresh_error"),
            "stale_cache": bool(metadata.get("stale_cache", False)),
            "refresh_in_progress": bool(metadata.get("refresh_in_progress", False)),
            "cache_dir": metadata.get("cache_dir"),
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

    def evaluate_csv(self, *, input_csv: str | Path, output_csv: str | Path, threshold: float | None = None) -> dict[str, Any]:
        from pipeline.evaluation.evaluate import evaluate_csv, build_report_payload

        def scorer(url: str, progress_callback=None):
            del progress_callback
            return self.scan_url(url)

        result = evaluate_csv(
            input_csv=input_csv,
            output_csv=output_csv,
            scorer=scorer,
            threshold=float(self.config.final_score_threshold if threshold is None else threshold),
        )
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
            "threshold": self.config.final_score_threshold,
            "fasttext_threshold": self.config.fasttext_threshold,
            "structured_ml": self.structured_ml.analytics(),
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
