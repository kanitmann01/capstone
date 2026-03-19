const evaluationForm = document.getElementById("evaluation-form");
const csvFileInput = document.getElementById("csv-file-input");
const thresholdInput = document.getElementById("threshold-input");
const startButton = document.getElementById("start-evaluation");
const fileSummary = document.getElementById("file-summary");
const statusEl = document.getElementById("eval-status");
const statusMessageEl = document.getElementById("eval-status-message");
const statusDetailEl = document.getElementById("eval-status-detail");
const jobBadge = document.getElementById("job-badge");
const progressFill = document.getElementById("progress-fill");
const progressText = document.getElementById("progress-text");
const progressPercent = document.getElementById("progress-percent");
const processedCount = document.getElementById("processed-count");
const scoredCount = document.getElementById("scored-count");
const errorCount = document.getElementById("error-count");
const currentUrl = document.getElementById("current-url");
const checkList = document.getElementById("check-list");
const recentRows = document.getElementById("recent-rows");
const reportShell = document.getElementById("report-shell");
const reportSummaryCards = document.getElementById("report-summary-cards");
const confusionMatrix = document.getElementById("confusion-matrix");
const scoreDistribution = document.getElementById("score-distribution");
const checkActivity = document.getElementById("check-activity");
const errorSummary = document.getElementById("error-summary");
const rowsTableBody = document.getElementById("rows-table-body");
const downloadReport = document.getElementById("download-report");
const tabButtons = Array.from(document.querySelectorAll(".tab-button"));
const tabPanels = Array.from(document.querySelectorAll(".tab-panel"));

const CHECK_ORDER = ["heuristics", "content", "ssl", "domain_age", "threat_intel", "ml"];
let activeJobId = null;
let pollTimer = null;
let loadingDetailTimer = null;
let pendingCsvText = "";
let lastStatusSignature = "";

const loadingDetails = [
  "Validating the uploaded baseline and counting labeled rows.",
  "Running each URL through the full check stack used in triage.",
  "Capturing mismatches, API errors, and score spread for the report.",
];

function defaultStatusDetail(tone) {
  if (tone === "danger") {
    return "The run needs attention before the report can be trusted.";
  }
  if (tone === "ok") {
    return "Use the finished report to inspect mismatches and edge cases before relying on the topline score.";
  }
  if (tone === "warn") {
    return "Live progress is still moving. Watch current checks, recent URLs, and error rows together.";
  }
  return "Once a run starts, this panel will call out progress, bottlenecks, and the next review step.";
}

function setStatus(message, tone = "muted", detail = defaultStatusDetail(tone)) {
  const signature = `${tone}::${message}::${detail}`;
  if (lastStatusSignature === signature) {
    return;
  }
  lastStatusSignature = signature;
  statusMessageEl.textContent = message;
  statusDetailEl.textContent = detail;
  statusEl.classList.remove("muted", "ok", "warn", "danger", "status-swap");
  statusEl.classList.add(tone);
  requestAnimationFrame(() => statusEl.classList.add("status-swap"));
}

function startLoadingDetails() {
  stopLoadingDetails();
  let index = 0;
  statusDetailEl.textContent = loadingDetails[index];
  loadingDetailTimer = window.setInterval(() => {
    index = (index + 1) % loadingDetails.length;
    statusDetailEl.textContent = loadingDetails[index];
  }, 1400);
}

function stopLoadingDetails() {
  if (loadingDetailTimer) {
    window.clearInterval(loadingDetailTimer);
    loadingDetailTimer = null;
  }
}

function replayEntrance(element) {
  element.classList.remove("panel-enter");
  void element.offsetWidth;
  element.classList.add("panel-enter");
}

function setBusy(isBusy, label = isBusy ? "Starting evaluation..." : "Start Evaluation") {
  startButton.disabled = isBusy;
  startButton.setAttribute("aria-busy", String(isBusy));
  startButton.textContent = label;
}

function setEvaluationControlsDisabled(isDisabled) {
  csvFileInput.disabled = isDisabled;
  thresholdInput.disabled = isDisabled;
}

function formatPercent(value) {
  return `${Number(value || 0).toFixed(1)}%`;
}

function predictionLabel(value) {
  if (value === true) return "Phishing";
  if (value === false) return "Legitimate";
  return "Unknown";
}

function truthLabel(value) {
  if (value === true) return "Phishing";
  if (value === false) return "Legitimate";
  return "Unknown";
}

function resultLabel(row) {
  if (row.api_error) return "Error";
  if (row.matched_ground_truth === true) return "Correct";
  if (row.matched_ground_truth === false) return "Mismatch";
  return "Pending";
}

function toneForJob(status) {
  if (status === "completed") return "ok";
  if (status === "failed") return "danger";
  if (status === "running" || status === "queued") return "warn";
  return "muted";
}

function checkStateLabel(state) {
  if (state === "running") return "Running";
  if (state === "completed") return "Completed";
  if (state === "unknown") return "Unknown";
  return "Queued";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderCheckList(states = {}) {
  checkList.innerHTML = "";
  CHECK_ORDER.forEach((check) => {
    const state = states[check] || "pending";
    const item = document.createElement("article");
    item.className = `check-item state-${state}`;
    item.innerHTML = `
      <div class="check-dot" aria-hidden="true"></div>
      <div class="check-copy">
        <strong>${escapeHtml(check.replaceAll("_", " "))}</strong>
        <span>${checkStateLabel(state)}</span>
      </div>
    `;
    checkList.appendChild(item);
  });
}

function renderRecentRows(rows) {
  if (!rows || rows.length === 0) {
    recentRows.className = "recent-stream empty-state";
    recentRows.textContent = "No websites processed yet.";
    return;
  }

  recentRows.className = "recent-stream";
  recentRows.innerHTML = rows
    .map((row) => {
      const score = row.risk_score == null ? "n/a" : Number(row.risk_score).toFixed(2);
      const tone = row.api_error ? "danger" : row.matched_ground_truth ? "ok" : "warn";
      return `
        <article class="recent-row">
          <div>
            <strong>${escapeHtml(row.url || row.scanned_url || "Unknown URL")}</strong>
            <span>${escapeHtml(resultLabel(row))}</span>
          </div>
          <span class="status-pill ${tone}">Score ${score}</span>
        </article>
      `;
    })
    .join("");
}

function renderJobState(job) {
  const tone = toneForJob(job.status);
  jobBadge.textContent = job.status === "completed" ? "Report Ready" : job.status;
  jobBadge.className = `summary-state ${tone}`;
  progressFill.style.width = `${job.progress_percent || 0}%`;
  progressText.textContent = `${job.processed_rows} of ${job.total_rows} websites processed`;
  progressPercent.textContent = formatPercent(job.progress_percent || 0);
  processedCount.textContent = String(job.processed_rows || 0);
  scoredCount.textContent = String(job.scored_rows || 0);
  errorCount.textContent = String(job.error_rows || 0);
  currentUrl.textContent = job.current_url || "Waiting for the next website...";
  renderCheckList(job.check_states);
  renderRecentRows(job.recent_rows);

  if (job.status === "failed") {
    setEvaluationControlsDisabled(false);
    setBusy(false);
    stopLoadingDetails();
    setStatus(job.message || "Evaluation failed.", "danger", "Review the upload, row-level errors, and any unavailable checks before retrying.");
  } else if (job.status === "completed") {
    setEvaluationControlsDisabled(false);
    setBusy(false);
    stopLoadingDetails();
    setStatus(job.message || "Evaluation finished.", "ok", "The report is ready. Start with mismatches and errors before drawing conclusions from accuracy alone.");
  } else {
    setEvaluationControlsDisabled(true);
    setBusy(true, "Evaluation in progress...");
    setStatus(job.message || "Evaluation in progress...", "warn", loadingDetails[1]);
  }
}

function renderSummaryCards(summary) {
  const cards = [
    ["Accuracy", summary.accuracy],
    ["Precision", summary.precision],
    ["Recall", summary.recall],
    ["F1", summary.f1],
    ["Scored Rows", summary.scored_rows],
    ["Error Rows", summary.error_rows],
  ];

  reportSummaryCards.innerHTML = cards
    .map(([label, value]) => {
      const text = typeof value === "number" && value <= 1 ? value.toFixed(4) : String(value);
      return `
        <article class="summary-metric-card">
          <span class="metric-label">${escapeHtml(label)}</span>
          <strong class="summary-metric-value">${escapeHtml(text)}</strong>
        </article>
      `;
    })
    .join("");
}

function renderConfusionMatrix(matrix) {
  const cells = [
    ["True Positives", matrix.tp, "danger"],
    ["False Positives", matrix.fp, "warn"],
    ["False Negatives", matrix.fn, "warn"],
    ["True Negatives", matrix.tn, "ok"],
  ];

  confusionMatrix.innerHTML = cells
    .map(
      ([label, value, tone]) => `
        <article class="matrix-cell tone-${tone}">
          <span>${escapeHtml(label)}</span>
          <strong>${escapeHtml(String(value))}</strong>
        </article>
      `,
    )
    .join("");
}

function renderHistogram(bins) {
  if (!bins || bins.length === 0) {
    scoreDistribution.className = "histogram empty-state";
    scoreDistribution.textContent = "No score data yet.";
    return;
  }

  const maxTotal = Math.max(...bins.map((bin) => bin.total), 1);
  scoreDistribution.className = "histogram";
  scoreDistribution.innerHTML = bins
    .map((bin) => {
      const phishingHeight = Math.max((bin.phishing / maxTotal) * 100, bin.phishing ? 6 : 0);
      const legitHeight = Math.max((bin.legitimate / maxTotal) * 100, bin.legitimate ? 6 : 0);
      return `
        <div class="histogram-bar-group">
          <div class="histogram-bar-stack">
            <span class="histogram-segment legit" style="height:${legitHeight}%"></span>
            <span class="histogram-segment phish" style="height:${phishingHeight}%"></span>
          </div>
          <span class="histogram-label">${escapeHtml(bin.label)}</span>
        </div>
      `;
    })
    .join("");
}

function renderMiniBars(target, items, emptyLabel, toneClass) {
  if (!items || items.length === 0) {
    target.className = "mini-bars empty-state";
    target.textContent = emptyLabel;
    return;
  }

  const max = Math.max(...items.map((item) => item.count), 1);
  target.className = "mini-bars";
  target.innerHTML = items
    .slice(0, 8)
    .map(
      (item) => `
        <div class="mini-bar-row">
          <span>${escapeHtml(item.check)}</span>
          <div class="mini-bar-track">
            <span class="mini-bar-fill ${toneClass}" style="width:${(item.count / max) * 100}%"></span>
          </div>
          <strong>${escapeHtml(String(item.count))}</strong>
        </div>
      `,
    )
    .join("");
}

function renderErrorSummary(items) {
  if (!items || items.length === 0) {
    errorSummary.className = "error-summary empty-state";
    errorSummary.textContent = "No errors recorded.";
    return;
  }

  errorSummary.className = "error-summary";
  errorSummary.innerHTML = items
    .map(
      (item) => `
        <article class="error-row">
          <strong>${escapeHtml(item.message)}</strong>
          <span class="status-pill warn">${escapeHtml(String(item.count))}</span>
        </article>
      `,
    )
    .join("");
}

function renderRowsTable(rows) {
  if (!rows || rows.length === 0) {
    rowsTableBody.innerHTML = `
      <tr>
        <td colspan="6" class="table-empty">No interesting rows returned for this run.</td>
      </tr>
    `;
    return;
  }

  rowsTableBody.innerHTML = rows
    .map((row) => {
      const score = row.risk_score == null ? "n/a" : Number(row.risk_score).toFixed(2);
      const result = resultLabel(row);
      const resultTone = row.api_error ? "danger" : row.matched_ground_truth ? "ok" : "warn";
      return `
        <tr>
          <td>${escapeHtml(String(row.index))}</td>
          <td class="table-url">
            <div>${escapeHtml(row.url || row.scanned_url || "Unknown URL")}</div>
            ${row.api_error ? `<small>${escapeHtml(row.api_error)}</small>` : ""}
          </td>
          <td>${escapeHtml(score)}</td>
          <td>${escapeHtml(predictionLabel(row.predicted_is_phishing))}</td>
          <td>${escapeHtml(truthLabel(row.actual_is_phishing))}</td>
          <td><span class="status-pill ${resultTone}">${escapeHtml(result)}</span></td>
        </tr>
      `;
    })
    .join("");
}

function renderReport(reportPayload, downloadUrl) {
  const report = reportPayload.report;
  reportShell.classList.remove("hidden");
  replayEntrance(reportShell);
  renderSummaryCards(report.summary);
  renderConfusionMatrix(report.confusion_matrix);
  renderHistogram(report.score_distribution);
  renderMiniBars(checkActivity, report.check_activity.contributing, "No contributing check data yet.", "primary");
  renderErrorSummary(report.errors);
  renderRowsTable(report.rows);

  if (downloadUrl) {
    downloadReport.href = downloadUrl;
    downloadReport.classList.remove("hidden");
  } else {
    downloadReport.classList.add("hidden");
  }
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Request failed.");
  }
  return payload;
}

async function loadReport(job) {
  if (!job.report_url) return;
  const reportPayload = await fetchJson(job.report_url);
  renderReport(reportPayload, job.download_url);
}

function schedulePoll(delay = 1200) {
  window.clearTimeout(pollTimer);
  pollTimer = window.setTimeout(pollJob, delay);
}

async function pollJob() {
  if (!activeJobId) return;
  try {
    const job = await fetchJson(`/evaluate/jobs/${activeJobId}`);
    renderJobState(job);
    if (job.status === "completed") {
      await loadReport(job);
      return;
    }
    if (job.status === "failed") {
      return;
    }
    schedulePoll();
  } catch (error) {
    stopLoadingDetails();
    setEvaluationControlsDisabled(false);
    setBusy(false);
    setStatus(error.message || "Unable to refresh evaluation progress.", "danger", "The run state may be stale until the next successful refresh.");
  }
}

csvFileInput.addEventListener("change", async () => {
  const [file] = csvFileInput.files || [];
  if (!file) {
    pendingCsvText = "";
    fileSummary.textContent = "No file selected yet.";
    return;
  }

  pendingCsvText = await file.text();
  const lineCount = pendingCsvText.trim() ? pendingCsvText.trim().split(/\r?\n/).length - 1 : 0;
  fileSummary.textContent = `${file.name} • ${lineCount} rows detected • ${(file.size / 1024).toFixed(1)} KB`;
  setStatus("Baseline file loaded.", "muted", "Threshold and row count look ready. Start the run when you want a live benchmark.");
});

evaluationForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const [file] = csvFileInput.files || [];
  if (!file) {
    setStatus("Choose a CSV file before starting.", "warn", "The evaluator expects labeled rows with url and is_phishing columns.");
    return;
  }

  try {
    setEvaluationControlsDisabled(true);
    setBusy(true, "Starting evaluation...");
    startLoadingDetails();
    const csvContent = pendingCsvText || (await file.text());
    const payload = await fetchJson("/evaluate/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: file.name,
        csv_content: csvContent,
        threshold: Number(thresholdInput.value || 50),
      }),
    });

    activeJobId = payload.job_id;
    reportShell.classList.add("hidden");
    renderJobState(payload);
    setStatus("Evaluation started. Progress will update automatically.", "warn", loadingDetails[0]);
    schedulePoll(600);
  } catch (error) {
    stopLoadingDetails();
    setEvaluationControlsDisabled(false);
    setBusy(false);
    setStatus(error.message || "Unable to start evaluation.", "danger", "The run did not start cleanly. Check the file format and try again.");
  }
});

tabButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const tabId = button.dataset.tab;
    tabButtons.forEach((candidate) => candidate.classList.toggle("is-active", candidate === button));
    tabPanels.forEach((panel) => panel.classList.toggle("is-active", panel.dataset.panel === tabId));
  });
});

renderCheckList();
