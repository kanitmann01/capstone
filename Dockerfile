FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TF_CPP_MIN_LOG_LEVEL=2 \
    TF_ENABLE_ONEDNN_OPTS=0 \
    CUDA_VISIBLE_DEVICES=-1 \
    APP_HOME=/app

WORKDIR ${APP_HOME}

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./requirements.txt
RUN python -m pip install --upgrade pip && \
    pip install -r requirements.txt

COPY . .

# Create non-root runtime user.
RUN groupadd --system appuser && \
    useradd --system --gid appuser --create-home appuser && \
    mkdir -p /app/.cache /app/data /app/models /app/docs && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# Container-friendly defaults for writable runtime artifacts.
ENV CAPSTONE_DATASET_DB=/app/.cache/brand-login-dataset.sqlite3 \
    THREAT_INTEL_CACHE_DIR=/app/.cache/threat-intel \
    FASTTEXT_MODEL_PATH=/app/.cache/fasttext/brand-login.bin \
    FASTTEXT_METADATA_PATH=/app/.cache/fasttext/brand-login.json \
    FASTTEXT_CORPUS_PATH=/app/data/processed/fasttext_corpus.txt \
    CAPSTONE_EVALUATION_DIR=/app/.cache/evaluations \
    ML_MODEL_PATH=/app/.cache/ml-artifacts/active_model.keras \
    ML_METADATA_PATH=/app/.cache/ml-artifacts/active_model.json \
    ML_RUNS_DIR=/app/.cache/ml-jobs

CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8000"]
