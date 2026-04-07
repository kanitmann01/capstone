from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Request
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.schemas import EvaluationJobRequest
from app.schemas import FastTextTrainingRequest
from app.schemas import URLRequest
from app.service import AppService


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
    return {
        "request": request,
        "title": title,
        "active_page": active_page,
        "nav_items": [
            {"href": "/", "label": "Scan Demo", "id": "scan"},
            {"href": "/dataset", "label": "Dataset & Analysis", "id": "dataset"},
            {"href": "/results", "label": "Results", "id": "results"},
        ],
    }


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        page_context(request, title="Fake Brand Login Detector", active_page="scan"),
    )


@app.get("/dataset", response_class=HTMLResponse)
async def dataset_page(request: Request):
    return templates.TemplateResponse(
        request,
        "dataset.html",
        {
            **page_context(request, title="Dataset & Analysis", active_page="dataset"),
            "dataset_summary": service.dataset_summary(),
            "dataset_recent_rows": service.dataset_recent(limit=10),
        },
    )


@app.get("/evaluate", response_class=HTMLResponse)
async def evaluate_page(request: Request):
    return await dataset_page(request)


@app.get("/results", response_class=HTMLResponse)
async def results_page(request: Request):
    return templates.TemplateResponse(
        request,
        "results.html",
        {
            **page_context(request, title="Results", active_page="results"),
            "model_overview": service.model_overview(),
            "latest_evaluation_report": service.latest_evaluation_report,
        },
    )


@app.get("/ml", response_class=HTMLResponse)
async def ml_page(request: Request):
    return await results_page(request)


@app.post("/scan/combined")
async def scan_combined(request: URLRequest):
    if not request.url.strip():
        raise HTTPException(status_code=400, detail="URL is required.")
    return scan_service.scan_combined(request.url)


@app.get("/dataset/summary")
async def dataset_summary():
    return service.dataset_summary()


@app.get("/dataset/recent")
async def dataset_recent(limit: int = 25):
    return service.dataset_recent(limit=limit)


@app.get("/models/overview")
async def models_overview():
    return service.model_overview()


@app.post("/evaluate")
async def evaluate(request: EvaluationJobRequest):
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
