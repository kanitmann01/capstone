from __future__ import annotations

"""
FastAPI route definitions and Jinja2 template rendering for the Fake Brand Login Detector.

This module exposes the REST API and web UI endpoints, wiring page-level services
from ``app.service`` into HTTP handlers. It mounts static assets, renders scan/demo
pages, and serves CSV downloads for evaluation jobs.
"""

import json  # Standard library: JSON loading for training reports
import re  # Standard library: regular expression utilities for safe filename validation
from pathlib import Path  # Standard library: filesystem path abstraction
from typing import Any  # Standard library: generic type hints
from urllib.parse import quote  # Standard library: percent-encoding for URL query values

from fastapi import FastAPI  # Third-party: ASGI web framework for building APIs
from fastapi import HTTPException  # Third-party: standardised HTTP error responses
from fastapi import Request  # Third-party: incoming HTTP request wrapper
from fastapi.responses import FileResponse  # Third-party: file download responses
from fastapi.responses import HTMLResponse  # Third-party: HTML page responses
from fastapi.staticfiles import StaticFiles  # Third-party: static asset serving
from fastapi.templating import Jinja2Templates  # Third-party: Jinja2 HTML template engine integration

from app.schemas import EvaluationJobRequest  # Project-local: Pydantic model for evaluation jobs
from app.schemas import FastTextTrainingRequest  # Project-local: Pydantic model for FastText training
from app.schemas import URLRequest  # Project-local: Pydantic model for URL scan requests
from app.service import AppService  # Project-local: core application service orchestrator


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEMPLATES_DIR = PROJECT_ROOT / "templates"
STATIC_DIR = PROJECT_ROOT / "static"

service = AppService()
scan_service = service
app = FastAPI(
    title="Fake Brand Login Detector API",
    description="Dataset-first fake brand login detection with FastText scoring and explanation signals.",
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def page_context(request: Request, *, title: str, active_page: str) -> dict[str, Any]:
    """Build common Jinja2 context for page templates."""
    return {
        "request": request,
        "title": title,
        "active_page": active_page,
        "nav_items": [
            {"href": "/", "label": "Check link", "id": "scan"},
            {"href": "/how-it-works", "label": "How it works", "id": "how"},
            {"href": "/dataset", "label": "Data & evaluation", "id": "dataset"},
            {"href": "/results", "label": "Model metrics", "id": "results"},
        ],
    }


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Render the scan demo landing page."""
    return templates.TemplateResponse(
        request,
        "index.html",
        page_context(request, title="Brand Guard - Check a link", active_page="scan"),
    )


@app.get("/how-it-works", response_class=HTMLResponse)
async def how_it_works_page(request: Request):
    """Explain the scan pipeline and scoring for curious users."""
    return templates.TemplateResponse(
        request,
        "how-it-works.html",
        {
            **page_context(request, title="Brand Guard - How it works", active_page="how"),
            "final_score_threshold": float(service.config.final_score_threshold),
        },
    )


@app.get("/dataset", response_class=HTMLResponse)
async def dataset_page(request: Request):
    """Render the dataset & analysis page."""
    return templates.TemplateResponse(
        request,
        "dataset.html",
        {
            **page_context(request, title="Brand Guard - Data & evaluation", active_page="dataset"),
            "dataset_summary": service.dataset_summary(),
            "dataset_recent_rows": service.dataset_recent(limit=10),
        },
    )


@app.get("/evaluate", response_class=HTMLResponse)
async def evaluate_page(request: Request):
    """Alias for the dataset page."""
    return await dataset_page(request)


def _load_json(path: Path) -> dict:
    """Load a JSON file, returning {} on any error."""
    try:
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception:
        return {}


def _load_roc_v2_data() -> dict[str, Any]:
    """Load ROC curve points for the results page chart.

    Tries the canonical ``models/improved_run/roc_data.json``, then any
    ``roc_data.json`` under ``models/`` (newest mtime), then under
    ``.cache/ml-artifacts/`` so charts still work if only a training run
    produced the file.
    """
    candidates: list[Path] = [
        PROJECT_ROOT / "models" / "improved_run" / "roc_data.json",
        PROJECT_ROOT / "data" / "processed" / "roc_v2.json",
        PROJECT_ROOT / "data" / "processed" / "roc_data.json",
    ]
    models_dir = PROJECT_ROOT / "models"
    if models_dir.is_dir():
        found = list(models_dir.rglob("roc_data.json"))
        found.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        for path in found:
            if path not in candidates:
                candidates.append(path)
    cache_dir = PROJECT_ROOT / ".cache" / "ml-artifacts"
    if cache_dir.is_dir():
        found = list(cache_dir.rglob("roc_data.json"))
        found.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        for path in found:
            if path not in candidates:
                candidates.append(path)
    seen: set[Path] = set()
    for path in candidates:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        data = _load_json(path)
        fpr = data.get("fpr")
        tpr = data.get("tpr")
        if isinstance(fpr, list) and isinstance(tpr, list) and len(fpr) >= 2 and len(fpr) == len(tpr):
            return data
    return {}


@app.get("/results", response_class=HTMLResponse)
async def results_page(request: Request):
    """Render the results / model overview page."""
    training_report_v1 = _load_json(PROJECT_ROOT / "models" / "run_20260424_093704" / "report.json")
    roc_v2 = _load_roc_v2_data()
    return templates.TemplateResponse(
        request,
        "results.html",
        {
            **page_context(request, title="Brand Guard - Model metrics", active_page="results"),
            "model_overview": service.model_overview(),
            "latest_evaluation_report": service.latest_evaluation_report,
            "training_report_v1": training_report_v1,
            "roc_v2": roc_v2,
        },
    )


@app.get("/ml", response_class=HTMLResponse)
async def ml_page(request: Request):
    """Alias for the results page."""
    return await results_page(request)


@app.post("/scan/combined")
async def scan_combined(request: URLRequest):
    """Run a combined phishing scan on the submitted URL."""
    if not request.url.strip():
        raise HTTPException(
            status_code=400,
            detail="Paste a web address (URL) to run a check.",
        )
    return scan_service.scan_combined(request.url)


@app.get("/dataset/summary")
async def dataset_summary():
    """Return aggregate statistics for the dataset store."""
    return service.dataset_summary()


@app.get("/dataset/recent")
async def dataset_recent(limit: int = 25):
    """Return the most recent dataset rows."""
    return service.dataset_recent(limit=limit)


@app.get("/models/overview")
async def models_overview():
    """Return metadata about currently configured detection models."""
    return service.model_overview()


@app.post("/evaluate")
async def evaluate(request: EvaluationJobRequest):
    """Run an ad-hoc evaluation job against a labeled CSV."""
    if not request.csv_content.strip():
        raise HTTPException(status_code=400, detail="CSV content is required.")
    tmp_dir = service.config.evaluation_dir / "ad_hoc"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    input_path = tmp_dir / f"{Path(request.filename or 'evaluation.csv').stem}_input.csv"
    output_path = tmp_dir / f"{Path(request.filename or 'evaluation.csv').stem}_scored.csv"
    input_path.write_text(request.csv_content, encoding="utf-8")
    report = service.evaluate_csv(input_csv=input_path, output_csv=output_path, threshold=request.threshold)
    eval_root = service.config.evaluation_dir.resolve()
    try:
        output_path.resolve().relative_to(eval_root)
    except ValueError as exc:
        raise HTTPException(
            status_code=500,
            detail="Evaluation output path is outside the configured evaluation directory.",
        ) from exc
    return {
        "report": report,
        "download_url": f"/evaluate/download?file={quote(output_path.name)}",
    }


_EVAL_DOWNLOAD_NAME = re.compile(r"^[A-Za-z0-9._-]+\.csv$")


@app.get("/evaluate/download")
async def evaluate_download(file: str):
    """Securely serve a scored CSV file from the evaluation directory."""
    if not file or not _EVAL_DOWNLOAD_NAME.fullmatch(file):
        raise HTTPException(status_code=400, detail="Invalid file name.")
    ad_hoc = (service.config.evaluation_dir / "ad_hoc").resolve()
    file_path = (ad_hoc / file).resolve()
    try:
        if not file_path.is_relative_to(ad_hoc):
            raise HTTPException(status_code=400, detail="Invalid download path.")
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail="Invalid download path.") from exc
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Scored CSV file was not found.")
    if file_path.suffix.lower() != ".csv":
        raise HTTPException(status_code=400, detail="Only CSV downloads are allowed.")
    return FileResponse(file_path, media_type="text/csv", filename=file_path.name)


@app.post("/train/fasttext")
async def train_fasttext(request: FastTextTrainingRequest):
    """Train a FastText model from an uploaded labeled CSV."""
    if not request.csv_content.strip():
        raise HTTPException(status_code=400, detail="CSV content is required.")
    tmp_dir = service.config.evaluation_dir / "training"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    input_path = tmp_dir / f"{Path(request.filename or 'training.csv').stem}_input.csv"
    input_path.write_text(request.csv_content, encoding="utf-8")
    report = service.train_fasttext_from_csv(
        input_csv=input_path,
        run_dir=tmp_dir / "run",
        activate_after_training=request.activate_after_training,
    )
    return report
