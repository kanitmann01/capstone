const evaluationForm = document.getElementById("evaluation-form");
const csvFileInput = document.getElementById("csv-file-input");
const thresholdInput = document.getElementById("threshold-input");
const startButton = document.getElementById("start-evaluation");
const fileSummary = document.getElementById("file-summary");
const statusEl = document.getElementById("eval-status");
const statusMessageEl = document.getElementById("eval-status-message");
const statusDetailEl = document.getElementById("eval-status-detail");
const reportShell = document.getElementById("report-shell");
const downloadReport = document.getElementById("download-report");

const totalMetric = document.getElementById("metric-total");
const scoredMetric = document.getElementById("metric-scored");
const accuracyMetric = document.getElementById("metric-accuracy");
const precisionMetric = document.getElementById("metric-precision");
const recallMetric = document.getElementById("metric-recall");
const f1Metric = document.getElementById("metric-f1");
const tpMetric = document.getElementById("metric-tp");
const tnMetric = document.getElementById("metric-tn");
const fpMetric = document.getElementById("metric-fp");
const fnMetric = document.getElementById("metric-fn");
const falsePositiveList = document.getElementById("false-positive-list");
const falseNegativeList = document.getElementById("false-negative-list");
const evaluationNote = document.getElementById("evaluation-note");

let pendingCsvText = "";

function setStatus(message, tone = "muted", detail = "Upload a CSV to run the reviewer workflow.") {
  statusMessageEl.textContent = message;
  statusDetailEl.textContent = detail;
  statusEl.classList.remove("muted", "ok", "warn", "danger");
  statusEl.classList.add(tone);
}

function setBusy(isBusy) {
  if (!startButton || !csvFileInput) return;
  startButton.disabled = isBusy;
  startButton.textContent = isBusy ? "Running Evaluation..." : "Run Evaluation";
  csvFileInput.disabled = isBusy;
}

function formatMetric(value, digits = 4) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return "n/a";
  }
  if (Math.abs(number) <= 1) {
    return number.toFixed(digits);
  }
  return String(Math.round(number * 100) / 100);
}

function setText(el, value) {
  if (!el) return;
  el.textContent = value;
}

function renderTokenList(target, items, emptyLabel) {
  if (!target) return;
  target.textContent = "";
  const list = Array.isArray(items) && items.length > 0 ? items : [emptyLabel];
  list.forEach((item) => {
    const token = document.createElement("span");
    token.className = "token";
    token.textContent = item;
    target.appendChild(token);
  });
}

function renderEvaluationReport(reportPayload) {
  const report = reportPayload.report || {};
  const summary = report.summary || {};
  const matrix = report.confusion_matrix || {};
  const falsePositives = report.false_positives || [];
  const falseNegatives = report.false_negatives || [];

  reportShell.classList.remove("hidden");
  setText(totalMetric, summary.total_rows ?? 0);
  setText(scoredMetric, summary.scored_rows ?? 0);
  setText(accuracyMetric, formatMetric(summary.accuracy));
  setText(precisionMetric, formatMetric(summary.precision));
  setText(recallMetric, formatMetric(summary.recall));
  setText(f1Metric, formatMetric(summary.f1));
  setText(tpMetric, matrix.tp ?? 0);
  setText(tnMetric, matrix.tn ?? 0);
  setText(fpMetric, matrix.fp ?? 0);
  setText(fnMetric, matrix.fn ?? 0);
  renderTokenList(
    falsePositiveList,
    falsePositives.map((item) => `${item.url} (${formatMetric(item.risk_score, 2)} · ${item.prediction || "unknown"})`),
    "No false positives",
  );
  renderTokenList(
    falseNegativeList,
    falseNegatives.map((item) => `${item.url} (${formatMetric(item.risk_score, 2)} · ${item.prediction || "unknown"})`),
    "No false negatives",
  );
  if (downloadReport && reportPayload.download_url) {
    downloadReport.href = reportPayload.download_url;
    downloadReport.textContent = "Download scored CSV";
  }
  evaluationNote.textContent = `Accuracy ${formatMetric(summary.accuracy)} | Precision ${formatMetric(summary.precision)} | Recall ${formatMetric(summary.recall)} | F1 ${formatMetric(summary.f1)}`;
  setStatus("Evaluation complete.", "ok", "Review the metrics and example mistakes below.");
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Request failed.");
  }
  return payload;
}

csvFileInput?.addEventListener("change", async () => {
  const [file] = csvFileInput.files || [];
  if (!file) {
    pendingCsvText = "";
    fileSummary.textContent = "Use a CSV with `url` and `is_phishing` columns.";
    return;
  }
  fileSummary.textContent = `Selected ${file.name}`;
  pendingCsvText = await file.text();
  const lineCount = pendingCsvText.trim() ? pendingCsvText.trim().split(/\r?\n/).length - 1 : 0;
  fileSummary.textContent = `${file.name} · ${lineCount} data rows ready`;
});

evaluationForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const [file] = csvFileInput.files || [];
  if (!file) {
    setStatus("Choose a CSV file first.", "warn", "Use the capstone features CSV or another labeled dataset.");
    return;
  }
  setBusy(true);
  setStatus("Running evaluation...", "muted", "Scoring the uploaded CSV against the current detector.");
  try {
    const csvContent = pendingCsvText || (await file.text());
    const payload = await fetchJson("/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: file.name,
        csv_content: csvContent,
        threshold: Number(thresholdInput?.value || 50),
      }),
    });
    renderEvaluationReport(payload);
  } catch (error) {
    setStatus(error.message || "Evaluation failed.", "danger", "The upload could not be scored. Check the CSV format and try again.");
  } finally {
    setBusy(false);
  }
});
