from contextlib import asynccontextmanager
from datetime import datetime
from datetime import timezone
from pathlib import Path
import json
import threading
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi import Request
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from evaluate_baseline import DEFAULT_THRESHOLD
from evaluate_baseline import build_check_states
from evaluate_baseline import build_report_payload
from evaluate_baseline import evaluate_csv
from scanner.feed_ingest import ThreatFeedCache
from scanner.ml_training import describe_tensorflow_runtime
from scanner.ml_training import load_model_registry
from scanner.ml_training import sanitize_training_config
from scanner.ml_training import train_from_labeled_csv
from scanner.service import ScanService
from scanner.settings import ScannerSettings

settings = ScannerSettings.from_env()
feed_cache = ThreatFeedCache(settings)
scan_service = ScanService(settings, feed_cache)
evaluation_jobs: dict[str, dict[str, Any]] = {}
evaluation_jobs_lock = threading.Lock()
evaluation_dir = Path(".cache/evaluations")
ml_jobs: dict[str, dict[str, Any]] = {}
ml_jobs_lock = threading.Lock()
ml_runs_dir = Path(settings.ml_runs_dir)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        feed_cache.refresh_now()
    except Exception:
        pass
    yield


app = FastAPI(
    title="Phishing Scanner API",
    description="API to scan URLs for phishing indicators.",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


class URLRequest(BaseModel):
    url: str


class EvaluationJobRequest(BaseModel):
    filename: str
    csv_content: str
    threshold: float = DEFAULT_THRESHOLD


class MLJobRequest(BaseModel):
    filename: str
    csv_content: str
    test_size: float | None = None
    random_state: int | None = None
    epochs: int | None = None
    batch_size: int | None = None
    learning_rate: float | None = None
    validation_split: float | None = None
    dropout_rate: float | None = None
    hidden_units: list[int] | None = None
    early_stopping_patience: int | None = None
    classification_threshold: float | None = None
    device: str | None = None
    activate_after_training: bool = True


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_stem(filename: str) -> str:
    raw_stem = Path(filename or "baseline.csv").stem or "baseline"
    cleaned = "".join(char if char.isalnum() or char in {"-", "_"} else "_" for char in raw_stem)
    return cleaned or "baseline"


def build_page_context(request: Request, *, title: str, active_page: str) -> dict[str, Any]:
    return {
        "request": request,
        "title": title,
        "active_page": active_page,
        "nav_items": [
            {"href": "/", "label": "Single Scan", "id": "scan"},
            {"href": "/evaluate", "label": "Batch Evaluation", "id": "evaluate"},
            {"href": "/ml", "label": "ML Lab", "id": "ml"},
        ],
    }


def summarize_recent_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "index": row.get("index"),
        "url": row.get("url"),
        "scanned_url": row.get("scanned_url"),
        "risk_score": row.get("risk_score"),
        "predicted_is_phishing": row.get("predicted_is_phishing"),
        "actual_is_phishing": row.get("actual_is_phishing"),
        "matched_ground_truth": row.get("matched_ground_truth"),
        "api_error": row.get("api_error"),
    }


def recent_ml_runs(limit: int = 8) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    seen_job_ids: set[str] = set()

    with ml_jobs_lock:
        jobs = sorted(
            ml_jobs.items(),
            key=lambda item: item[1].get("created_at", ""),
            reverse=True,
        )
        for job_id, job in jobs:
            report = job.get("report") or {}
            summary = report.get("summary") or {}
            summaries.append(
                {
                    "job_id": job_id,
                    "status": job.get("status"),
                    "input_filename": job.get("input_filename"),
                    "created_at": job.get("created_at"),
                    "completed_at": job.get("completed_at"),
                    "model_version": summary.get("model_version"),
                    "accuracy": summary.get("accuracy"),
                    "f1": summary.get("f1"),
                    "report_ready": report != {},
                    "report_url": f"/ml/jobs/{job_id}/report" if report != {} else None,
                }
            )
            seen_job_ids.add(job_id)

    for entry in load_model_registry(settings):
        job_id = str(entry.get("job_id") or "")
        if not job_id or job_id in seen_job_ids:
            continue
        summaries.append(
            {
                "job_id": job_id,
                "status": entry.get("status", "completed"),
                "input_filename": entry.get("input_filename"),
                "created_at": entry.get("created_at"),
                "completed_at": entry.get("completed_at"),
                "model_version": entry.get("model_version"),
                "accuracy": entry.get("accuracy"),
                "f1": entry.get("f1"),
                "report_ready": True,
                "report_url": f"/ml/jobs/{job_id}/report",
            }
        )

    summaries.sort(key=lambda item: str(item.get("created_at") or item.get("completed_at") or ""), reverse=True)
    return summaries[:limit]


def public_job_state(job_id: str) -> dict[str, Any]:
    with evaluation_jobs_lock:
        job = evaluation_jobs.get(job_id)
        if job is None:
            raise KeyError(job_id)
        total_rows = int(job.get("total_rows", 0) or 0)
        processed_rows = int(job.get("processed_rows", 0) or 0)
        progress_percent = job.get("progress_percent")
        if progress_percent is None:
            progress_percent = round((processed_rows / total_rows) * 100, 1) if total_rows else 0.0
        return {
            "job_id": job_id,
            "status": job["status"],
            "message": job.get("message", ""),
            "input_filename": job["input_filename"],
            "threshold": job["threshold"],
            "created_at": job["created_at"],
            "started_at": job.get("started_at"),
            "completed_at": job.get("completed_at"),
            "failed_at": job.get("failed_at"),
            "total_rows": total_rows,
            "processed_rows": processed_rows,
            "scored_rows": job.get("scored_rows", 0),
            "error_rows": job.get("error_rows", 0),
            "progress_percent": progress_percent,
            "current_row_index": job.get("current_row_index", 0),
            "current_url": job.get("current_url", ""),
            "check_states": dict(job.get("check_states", {})),
            "recent_rows": list(job.get("recent_rows", [])),
            "report_ready": job.get("report") is not None,
            "report_url": f"/evaluate/jobs/{job_id}/report" if job.get("report") is not None else None,
            "download_url": f"/evaluate/jobs/{job_id}/download" if job.get("status") == "completed" else None,
        }


def public_ml_job_state(job_id: str) -> dict[str, Any]:
    with ml_jobs_lock:
        job = ml_jobs.get(job_id)
        if job is None:
            raise KeyError(job_id)
        return {
            "job_id": job_id,
            "status": job["status"],
            "message": job.get("message", ""),
            "input_filename": job["input_filename"],
            "created_at": job["created_at"],
            "started_at": job.get("started_at"),
            "completed_at": job.get("completed_at"),
            "failed_at": job.get("failed_at"),
            "progress_percent": float(job.get("progress_percent", 0.0)),
            "current_phase": job.get("current_phase", "queued"),
            "current_url": job.get("current_url", ""),
            "total_rows": int(job.get("total_rows", 0) or 0),
            "processed_rows": int(job.get("processed_rows", 0) or 0),
            "usable_rows": int(job.get("usable_rows", 0) or 0),
            "skipped_rows": int(job.get("skipped_rows", 0) or 0),
            "check_states": dict(job.get("check_states", {})),
            "recent_rows": list(job.get("recent_rows", [])),
            "config": dict(job.get("config", {})),
            "report_ready": job.get("report") is not None,
            "report_url": f"/ml/jobs/{job_id}/report" if job.get("report") is not None else None,
        }


def update_job_progress(job_id: str, event: dict[str, Any]) -> None:
    with evaluation_jobs_lock:
        job = evaluation_jobs.get(job_id)
        if job is None:
            return
        event_type = event.get("type")
        if event_type == "job_started":
            job["status"] = "running"
            job["message"] = "Scanning uploaded baseline..."
            job["total_rows"] = int(event.get("total_rows", 0) or 0)
            return

        if event_type in {"row_started", "check_started", "check_completed", "row_completed"}:
            job["current_row_index"] = int(event.get("row_index", job.get("current_row_index", 0)) or 0)
            job["current_url"] = event.get("url", job.get("current_url", ""))
            job["processed_rows"] = int(event.get("processed_rows", job.get("processed_rows", 0)) or 0)
            job["scored_rows"] = int(event.get("scored_rows", job.get("scored_rows", 0)) or 0)
            job["error_rows"] = int(event.get("error_rows", job.get("error_rows", 0)) or 0)
            job["check_states"] = dict(event.get("check_states", job.get("check_states", {})))

        if event_type == "row_completed" and event.get("row"):
            recent_rows = job.setdefault("recent_rows", [])
            recent_rows.insert(0, summarize_recent_row(event["row"]))
            del recent_rows[10:]
            job["message"] = f"Processed {job['processed_rows']} of {job['total_rows']} websites."
        elif event_type == "check_started":
            job["message"] = f"Running {event.get('check')} checks for the current website..."
        elif event_type == "check_completed":
            job["message"] = f"Completed {event.get('check')} checks."


def update_ml_job_progress(job_id: str, event: dict[str, Any]) -> None:
    with ml_jobs_lock:
        job = ml_jobs.get(job_id)
        if job is None:
            return
        event_type = event.get("type")
        if event_type == "job_started":
            job["status"] = "running"
            job["message"] = event.get("message", "Preparing ML run...")
            job["total_rows"] = int(event.get("total_rows", 0) or 0)
            job["progress_percent"] = float(event.get("progress_percent", 0.0))
            job["current_phase"] = str(event.get("phase", "prepare_dataset"))
            return
        if event_type == "stage_changed":
            job["current_phase"] = str(event.get("phase", job.get("current_phase", "running")))
            job["message"] = event.get("message", job.get("message", "ML run in progress..."))
            job["progress_percent"] = float(event.get("progress_percent", job.get("progress_percent", 0.0)))
            return
        if event_type in {"row_started", "row_completed", "check_started", "check_completed"}:
            job["current_url"] = event.get("url", job.get("current_url", ""))
            if "processed_rows" in event:
                job["processed_rows"] = int(event.get("processed_rows", 0) or 0)
            if "usable_rows" in event:
                job["usable_rows"] = int(event.get("usable_rows", 0) or 0)
            if "skipped_rows" in event:
                job["skipped_rows"] = int(event.get("skipped_rows", 0) or 0)
            if "progress_percent" in event:
                job["progress_percent"] = float(event.get("progress_percent", 0.0))
        if event_type == "row_started":
            job["check_states"] = build_check_states()
        if event_type == "check_started":
            check_states = dict(job.get("check_states", {}))
            check_states[str(event.get("check"))] = "running"
            job["check_states"] = check_states
        elif event_type == "check_completed":
            check_states = dict(job.get("check_states", {}))
            check_states[str(event.get("check"))] = (
                "completed" if str(event.get("status", "ok")) == "ok" else "unknown"
            )
            job["check_states"] = check_states
        elif event_type == "row_completed":
            recent_rows = job.setdefault("recent_rows", [])
            recent_rows.insert(
                0,
                {
                    "index": event.get("row_index"),
                    "url": event.get("url"),
                    "usable_rows": job.get("usable_rows", 0),
                    "skipped_rows": job.get("skipped_rows", 0),
                },
            )
            del recent_rows[10:]
            job["message"] = (
                f"Extracted features for {job.get('processed_rows', 0)} of {job.get('total_rows', 0)} URLs."
            )


def run_evaluation_job(job_id: str) -> None:
    with evaluation_jobs_lock:
        job = evaluation_jobs[job_id]
        job["status"] = "running"
        job["started_at"] = utc_now_iso()
        input_path = Path(job["input_csv_path"])
        output_path = Path(job["output_csv_path"])
        threshold = float(job["threshold"])

    try:
        result = evaluate_csv(
            input_csv=input_path,
            output_csv=output_path,
            threshold=threshold,
            scorer=lambda url, callback: scan_service.scan_combined_with_progress(
                url,
                progress_callback=callback,
            ),
            progress_callback=lambda event: update_job_progress(job_id, event),
        )
        report = build_report_payload(result)

        with evaluation_jobs_lock:
            job = evaluation_jobs[job_id]
            job["status"] = "completed"
            job["completed_at"] = utc_now_iso()
            job["processed_rows"] = result.total_rows
            job["scored_rows"] = result.scored_rows
            job["error_rows"] = result.error_rows
            job["total_rows"] = result.total_rows
            job["current_url"] = ""
            job["current_row_index"] = result.total_rows
            job["message"] = "Evaluation finished. Report ready."
            job["report"] = report
    except Exception as exc:
        with evaluation_jobs_lock:
            job = evaluation_jobs[job_id]
            job["status"] = "failed"
            job["failed_at"] = utc_now_iso()
            job["message"] = str(exc)
            job["current_url"] = ""


def run_ml_job(job_id: str) -> None:
    with ml_jobs_lock:
        job = ml_jobs[job_id]
        job["status"] = "running"
        job["started_at"] = utc_now_iso()
        job["current_phase"] = "prepare_dataset"
        input_path = Path(job["input_csv_path"])
        job_dir = Path(job["job_dir"])
        config_payload = dict(job["config"])

    try:
        config = sanitize_training_config(config_payload, settings)
        report = train_from_labeled_csv(
            input_csv=input_path,
            run_dir=job_dir,
            scan_service=scan_service,
            settings=settings,
            config=config,
            input_filename=job["input_filename"],
            label_source="uploaded_csv",
            progress_callback=lambda event: update_ml_job_progress(job_id, event),
        )
        if config.activate_after_training:
            scan_service.ml_scanner.refresh()

        with ml_jobs_lock:
            job = ml_jobs[job_id]
            job["status"] = "completed"
            job["completed_at"] = utc_now_iso()
            job["current_phase"] = "completed"
            job["current_url"] = ""
            job["message"] = "ML training finished. Report ready."
            job["progress_percent"] = 100.0
            job["report"] = report
    except Exception as exc:
        with ml_jobs_lock:
            job = ml_jobs[job_id]
            job["status"] = "failed"
            job["failed_at"] = utc_now_iso()
            job["current_phase"] = "failed"
            job["message"] = str(exc)
            job["current_url"] = ""


@app.get("/", response_class=HTMLResponse)
async def web_home(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        build_page_context(request, title="Phishing Scanner", active_page="scan"),
    )


@app.get("/evaluate", response_class=HTMLResponse)
async def evaluation_page(request: Request):
    return templates.TemplateResponse(
        request,
        "evaluation.html",
        build_page_context(request, title="Baseline Evaluation", active_page="evaluate"),
    )


@app.get("/ml", response_class=HTMLResponse)
async def ml_page(request: Request):
    return templates.TemplateResponse(
        request,
        "ml.html",
        build_page_context(request, title="ML Lab", active_page="ml"),
    )


@app.post("/scan/combined")
async def scan_combined(request: URLRequest):
    try:
        return await run_in_threadpool(scan_service.scan_combined, request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/scan/heuristics")
async def scan_heuristics(request: URLRequest):
    try:
        return await run_in_threadpool(scan_service.scan_heuristics, request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/scan/content")
async def scan_content(request: URLRequest):
    try:
        return await run_in_threadpool(scan_service.scan_content, request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/scan/ssl")
async def scan_ssl(request: URLRequest):
    try:
        return await run_in_threadpool(scan_service.scan_ssl, request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/scan/whois")
async def scan_whois(request: URLRequest):
    try:
        return await run_in_threadpool(scan_service.scan_whois, request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/scan/threats")
async def scan_threats(request: URLRequest):
    try:
        return await run_in_threadpool(scan_service.scan_threats, request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/scan/ml")
async def scan_ml(request: URLRequest):
    try:
        return await run_in_threadpool(scan_service.scan_ml, request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/ml/overview")
async def ml_overview():
    return {
        "active_model": await run_in_threadpool(scan_service.ml_overview),
        "recent_jobs": recent_ml_runs(),
        "model_registry": load_model_registry(settings),
        "runtime": describe_tensorflow_runtime(),
        "training_defaults": {
            "test_size": settings.ml_default_test_size,
            "random_state": settings.ml_default_random_state,
            "epochs": settings.ml_default_epochs,
            "batch_size": settings.ml_default_batch_size,
            "learning_rate": settings.ml_default_learning_rate,
            "validation_split": settings.ml_default_validation_split,
            "dropout_rate": settings.ml_default_dropout_rate,
            "hidden_units": [int(value) for value in settings.ml_default_hidden_units.split(",") if value.strip()],
            "early_stopping_patience": settings.ml_default_early_stopping_patience,
            "classification_threshold": settings.ml_default_classification_threshold,
            "device": settings.ml_default_device,
            "activate_after_training": settings.ml_default_activate_after_training,
        },
    }


@app.post("/feeds/refresh")
async def refresh_feeds():
    return await run_in_threadpool(scan_service.refresh_feeds)


@app.post("/evaluate/jobs")
async def create_evaluation_job(request: EvaluationJobRequest):
    if not request.csv_content.strip():
        raise HTTPException(status_code=400, detail="CSV content is required.")
    if request.threshold < 0 or request.threshold > 100:
        raise HTTPException(status_code=400, detail="Threshold must be between 0 and 100.")

    job_id = uuid4().hex
    job_dir = evaluation_dir / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    input_filename = request.filename or "baseline.csv"
    input_path = job_dir / f"{safe_stem(input_filename)}_input.csv"
    output_path = job_dir / f"{safe_stem(input_filename)}_scored.csv"
    input_path.write_text(request.csv_content, encoding="utf-8")

    with evaluation_jobs_lock:
        evaluation_jobs[job_id] = {
            "status": "queued",
            "message": "Upload received. Preparing evaluation...",
            "input_filename": input_filename,
            "threshold": float(request.threshold),
            "created_at": utc_now_iso(),
            "started_at": None,
            "completed_at": None,
            "failed_at": None,
            "input_csv_path": str(input_path),
            "output_csv_path": str(output_path),
            "total_rows": 0,
            "processed_rows": 0,
            "scored_rows": 0,
            "error_rows": 0,
            "current_row_index": 0,
            "current_url": "",
            "check_states": build_check_states(),
            "recent_rows": [],
            "report": None,
        }

    threading.Thread(target=run_evaluation_job, args=(job_id,), daemon=True).start()
    return public_job_state(job_id)


@app.post("/ml/jobs")
async def create_ml_job(request: MLJobRequest):
    if not request.csv_content.strip():
        raise HTTPException(status_code=400, detail="CSV content is required.")
    job_id = uuid4().hex
    job_dir = ml_runs_dir / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    input_filename = request.filename or "baseline.csv"
    input_path = job_dir / f"{safe_stem(input_filename)}_input.csv"
    input_path.write_text(request.csv_content, encoding="utf-8")

    config_payload = {
        "test_size": request.test_size,
        "random_state": request.random_state,
        "epochs": request.epochs,
        "batch_size": request.batch_size,
        "learning_rate": request.learning_rate,
        "validation_split": request.validation_split,
        "dropout_rate": request.dropout_rate,
        "hidden_units": request.hidden_units,
        "early_stopping_patience": request.early_stopping_patience,
        "classification_threshold": request.classification_threshold,
        "device": request.device,
        "activate_after_training": request.activate_after_training,
    }
    try:
        sanitize_training_config(config_payload, settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    with ml_jobs_lock:
        ml_jobs[job_id] = {
            "status": "queued",
            "message": "Upload received. Preparing ML run...",
            "input_filename": input_filename,
            "created_at": utc_now_iso(),
            "started_at": None,
            "completed_at": None,
            "failed_at": None,
            "job_dir": str(job_dir),
            "input_csv_path": str(input_path),
            "progress_percent": 0.0,
            "current_phase": "queued",
            "current_url": "",
            "total_rows": 0,
            "processed_rows": 0,
            "usable_rows": 0,
            "skipped_rows": 0,
            "check_states": build_check_states(),
            "recent_rows": [],
            "config": config_payload,
            "report": None,
        }

    threading.Thread(target=run_ml_job, args=(job_id,), daemon=True).start()
    return public_ml_job_state(job_id)


@app.get("/evaluate/jobs/{job_id}")
async def evaluation_job_status(job_id: str):
    try:
        return public_job_state(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Evaluation job not found.") from exc


@app.get("/ml/jobs/{job_id}")
async def ml_job_status(job_id: str):
    try:
        return public_ml_job_state(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="ML job not found.") from exc


@app.get("/evaluate/jobs/{job_id}/report")
async def evaluation_job_report(job_id: str):
    with evaluation_jobs_lock:
        job = evaluation_jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Evaluation job not found.")
        if job.get("report") is None:
            if job["status"] == "failed":
                raise HTTPException(status_code=409, detail=job.get("message", "Evaluation failed."))
            raise HTTPException(status_code=409, detail="Evaluation is still running.")
        return {
            "job_id": job_id,
            "input_filename": job["input_filename"],
            "threshold": job["threshold"],
            "completed_at": job.get("completed_at"),
            "download_url": f"/evaluate/jobs/{job_id}/download",
            "report": job["report"],
        }


@app.get("/ml/jobs/{job_id}/report")
async def ml_job_report(job_id: str):
    with ml_jobs_lock:
        job = ml_jobs.get(job_id)
        if job is not None:
            if job.get("report") is None:
                if job["status"] == "failed":
                    raise HTTPException(status_code=409, detail=job.get("message", "ML run failed."))
                raise HTTPException(status_code=409, detail="ML job is still running.")
            return {
                "job_id": job_id,
                "input_filename": job["input_filename"],
                "completed_at": job.get("completed_at"),
                "report": job["report"],
            }

    registry_entry = next((entry for entry in load_model_registry(settings) if entry.get("job_id") == job_id), None)
    if registry_entry is None:
        raise HTTPException(status_code=404, detail="ML job not found.")

    artifacts = registry_entry.get("artifacts") or {}
    report_path_raw = artifacts.get("report_path")
    if not report_path_raw:
        raise HTTPException(status_code=404, detail="Stored ML report is unavailable.")

    report_path = Path(report_path_raw)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Stored ML report file is unavailable.")

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Stored ML report is invalid: {exc}") from exc

    return {
        "job_id": job_id,
        "input_filename": registry_entry.get("input_filename"),
        "completed_at": registry_entry.get("completed_at"),
        "report": report,
    }


@app.get("/ml/runs/recent")
async def ml_jobs_recent():
    return {"jobs": recent_ml_runs()}


@app.get("/evaluate/jobs/{job_id}/download")
async def evaluation_job_download(job_id: str):
    with evaluation_jobs_lock:
        job = evaluation_jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Evaluation job not found.")
        if job["status"] != "completed":
            raise HTTPException(status_code=409, detail="Evaluation is not finished yet.")
        output_path = Path(job["output_csv_path"])
        filename = f"{safe_stem(job['input_filename'])}_scored.csv"

    if not output_path.exists():
        raise HTTPException(status_code=404, detail="Output CSV is unavailable.")
    return FileResponse(output_path, media_type="text/csv", filename=filename)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
