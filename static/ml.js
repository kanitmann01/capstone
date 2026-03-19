const mlForm = document.getElementById("ml-form");
const mlCsvFileInput = document.getElementById("ml-csv-file-input");
const mlFileSummary = document.getElementById("ml-file-summary");
const startMlTraining = document.getElementById("start-ml-training");
const deviceInput = document.getElementById("device-input");
const epochsInput = document.getElementById("epochs-input");
const batchSizeInput = document.getElementById("batch-size-input");
const learningRateInput = document.getElementById("learning-rate-input");
const testSizeInput = document.getElementById("test-size-input");
const validationSplitInput = document.getElementById("validation-split-input");
const dropoutRateInput = document.getElementById("dropout-rate-input");
const hiddenUnitsInput = document.getElementById("hidden-units-input");
const earlyStoppingInput = document.getElementById("early-stopping-input");
const thresholdInput = document.getElementById("threshold-input");
const randomStateInput = document.getElementById("random-state-input");
const mlRuntimeSummary = document.getElementById("ml-runtime-summary");
const mlRuntimeNote = document.getElementById("ml-runtime-note");
const activateModelInput = document.getElementById("activate-model-input");
const statusEl = document.getElementById("ml-status");
const statusMessageEl = document.getElementById("ml-status-message");
const statusDetailEl = document.getElementById("ml-status-detail");

const activeModelBadge = document.getElementById("active-model-badge");
const activeModelMetrics = document.getElementById("active-model-metrics");
const activeTopFeatures = document.getElementById("active-top-features");
const activeModelAnalytics = document.getElementById("active-model-analytics");

const mlJobBadge = document.getElementById("ml-job-badge");
const mlProgressFill = document.getElementById("ml-progress-fill");
const mlProgressText = document.getElementById("ml-progress-text");
const mlProgressPercent = document.getElementById("ml-progress-percent");
const mlProcessedCount = document.getElementById("ml-processed-count");
const mlUsableCount = document.getElementById("ml-usable-count");
const mlSkippedCount = document.getElementById("ml-skipped-count");
const mlCurrentPhase = document.getElementById("ml-current-phase");
const mlCurrentUrl = document.getElementById("ml-current-url");
const mlCheckList = document.getElementById("ml-check-list");
const mlRecentRows = document.getElementById("ml-recent-rows");

const mlReportShell = document.getElementById("ml-report-shell");
const mlSummaryCards = document.getElementById("ml-summary-cards");
const mlConfusionMatrix = document.getElementById("ml-confusion-matrix");
const mlTreeSummary = document.getElementById("ml-tree-summary");
const mlHyperparameters = document.getElementById("ml-hyperparameters");
const mlErrorAnalysis = document.getElementById("ml-error-analysis");
const mlArtifactLinks = document.getElementById("ml-artifact-links");
const mlRecentRuns = document.getElementById("ml-recent-runs");
const mlRegistryHighlights = document.getElementById("ml-registry-highlights");
const mlRegistryCompare = document.getElementById("ml-registry-compare");
const mlTabButtons = Array.from(document.querySelectorAll("[data-ml-tab]"));
const mlTabPanels = Array.from(document.querySelectorAll("[data-ml-panel]"));

const mlProbeForm = document.getElementById("ml-probe-form");
const mlProbeUrl = document.getElementById("ml-probe-url");
const mlProbeResult = document.getElementById("ml-probe-result");
const runMlProbe = document.getElementById("run-ml-probe");

const CHECK_ORDER = ["heuristics", "content", "ssl", "domain_age", "threat_intel", "ml"];
let activeJobId = null;
let pollTimer = null;
let loadingDetailTimer = null;
let runtimeDefaultsInitialized = false;
let pendingCsvText = "";
let lastStatusSignature = "";
const charts = {};
const rootStyles = getComputedStyle(document.documentElement);

const loadingDetails = [
  "Validating the labeled dataset and preparing feature extraction.",
  "Building row-level features from lexical, metadata, and scanner signals.",
  "Training the TensorFlow model, writing TensorBoard logs, and selecting the best checkpoint.",
];

function cssVar(name, fallback) {
  const value = rootStyles.getPropertyValue(name).trim();
  return value || fallback;
}

const chartTheme = {
  primary: cssVar("--chart-primary", "rgba(34, 96, 201, 0.82)"),
  success: cssVar("--chart-success", "rgba(19, 155, 103, 0.78)"),
  danger: cssVar("--chart-danger", "rgba(197, 58, 58, 0.78)"),
  warning: cssVar("--chart-warning", "rgba(180, 118, 21, 0.82)"),
  violet: cssVar("--chart-violet", "rgba(103, 80, 214, 0.8)"),
  text: cssVar("--chart-text", "#334155"),
  mutedText: cssVar("--chart-text-soft", "#64748b"),
  grid: cssVar("--chart-grid", "rgba(133, 153, 186, 0.18)"),
};

function defaultStatusDetail(tone) {
  if (tone === "danger") {
    return "The lab needs attention before this run or probe can be trusted.";
  }
  if (tone === "ok") {
    return "Use the report to compare generalization quality, not just train-time confidence.";
  }
  if (tone === "warn") {
    return "The lab is still working. Watch phase changes, skipped rows, and model readiness together.";
  }
  return "This panel will narrate training phases, model readiness, and what to inspect next.";
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
  }, 1450);
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

function setBusy(isBusy, label = isBusy ? "Starting run..." : "Start ML Run") {
  startMlTraining.disabled = isBusy;
  startMlTraining.setAttribute("aria-busy", String(isBusy));
  startMlTraining.textContent = label;
}

function setProbeBusy(isBusy) {
  if (!runMlProbe) return;
  runMlProbe.disabled = isBusy;
  runMlProbe.setAttribute("aria-busy", String(isBusy));
  runMlProbe.textContent = isBusy ? "Running probe..." : "Run ML Scan";
}

function setTrainingControlsDisabled(isDisabled) {
  [
    mlCsvFileInput,
    deviceInput,
    epochsInput,
    batchSizeInput,
    learningRateInput,
    testSizeInput,
    validationSplitInput,
    dropoutRateInput,
    hiddenUnitsInput,
    earlyStoppingInput,
    thresholdInput,
    randomStateInput,
    activateModelInput,
  ].forEach((element) => {
    if (!element) return;
    element.disabled = isDisabled;
  });
}

function toneForStatus(status) {
  if (status === "completed") return "ok";
  if (status === "failed") return "danger";
  if (status === "running" || status === "queued") return "warn";
  return "muted";
}

function formatMetric(value) {
  if (typeof value === "number") {
    if (value <= 1) return value.toFixed(4);
    return String(Number(value.toFixed(2)));
  }
  return value == null || value === "" ? "n/a" : String(value);
}

function titleCaseWords(value) {
  return String(value)
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => {
      const lower = word.toLowerCase();
      if (lower === "ml") return "ML";
      if (lower === "url") return "URL";
      if (lower.length <= 2 && /\d/.test(lower) === false) return lower.toUpperCase();
      return lower.charAt(0).toUpperCase() + lower.slice(1);
    })
    .join(" ");
}

function humanizeIdentifier(value) {
  if (value == null || value === "") return "n/a";
  return titleCaseWords(String(value).replaceAll(/[_-]+/g, " "));
}

function formatModelType(value) {
  if (!value) return "TensorFlow Dense";
  if (String(value).toLowerCase() === "tensorflow_dense") return "TensorFlow Dense";
  if (String(value).toLowerCase() === "decision_tree") return "Decision Tree";
  return humanizeIdentifier(value);
}

function formatModelVersion(value) {
  if (!value) return "none";
  return humanizeIdentifier(value);
}

function formatFeatureSchema(value) {
  if (!value) return "n/a";
  return humanizeIdentifier(value);
}

function formatProbabilityPercent(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "n/a";
  return `${(number * 100).toFixed(1)}%`;
}

function formatTimestamp(value) {
  if (!value) return "n/a";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
  }).format(date) + " UTC";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Request failed.");
  }
  return payload;
}

function renderCheckList(states = {}) {
  mlCheckList.innerHTML = "";
  CHECK_ORDER.forEach((check) => {
    const state = states[check] || "pending";
    const item = document.createElement("article");
    item.className = `check-item state-${state}`;
    item.innerHTML = `
      <div class="check-dot" aria-hidden="true"></div>
      <div class="check-copy">
        <strong>${escapeHtml(check.replaceAll("_", " "))}</strong>
        <span>${escapeHtml(state)}</span>
      </div>
    `;
    mlCheckList.appendChild(item);
  });
}

function renderMiniBars(target, items, { labelKey = "feature", valueKey = "importance", toneClass = "primary", emptyLabel = "No data yet.", formatter = (value) => formatMetric(value) } = {}) {
  if (!items || items.length === 0) {
    target.className = "mini-bars empty-state";
    target.textContent = emptyLabel;
    return;
  }
  const max = Math.max(...items.map((item) => Number(item[valueKey] || 0)), 1);
  target.className = "mini-bars";
  target.innerHTML = items
    .slice(0, 8)
    .map(
      (item) => `
        <div class="mini-bar-row">
          <span>${escapeHtml(item[labelKey])}</span>
          <div class="mini-bar-track">
            <span class="mini-bar-fill ${toneClass}" style="width:${(Number(item[valueKey] || 0) / max) * 100}%"></span>
          </div>
          <strong>${escapeHtml(formatter(item[valueKey]))}</strong>
        </div>
      `,
    )
    .join("");
}

function renderMetricCards(target, items) {
  target.innerHTML = items
    .map(
      (item) => {
        const normalized = Array.isArray(item)
          ? { label: item[0], value: item[1] }
          : item;
        const variant = normalized.variant || "stat";
        const displayValue =
          normalized.displayValue != null ? normalized.displayValue : formatMetric(normalized.value);
        const meta = normalized.meta ? `<span class="metric-meta">${escapeHtml(normalized.meta)}</span>` : "";
        return `
        <article class="summary-metric-card metric-card-${escapeHtml(variant)}">
          <span class="metric-label">${escapeHtml(normalized.label)}</span>
          <strong class="summary-metric-value">${escapeHtml(displayValue)}</strong>
          ${meta}
        </article>
      `;
      },
    )
    .join("");
}

function renderActiveModel(activeModel) {
  const tone = activeModel?.available ? "ok" : activeModel?.enabled ? "warn" : "muted";
  const label = activeModel?.available ? "Active" : activeModel?.enabled ? "Waiting For Model" : "Disabled";
  activeModelBadge.textContent = label;
  activeModelBadge.className = `summary-state ${tone}`;

  renderMetricCards(activeModelMetrics, [
    {
      label: "Version",
      value: activeModel?.model_version,
      displayValue: formatModelVersion(activeModel?.model_version),
      variant: "text",
    },
    {
      label: "Type",
      value: activeModel?.model_type,
      displayValue: formatModelType(activeModel?.model_type),
      variant: "text",
    },
    {
      label: "Feature Schema",
      value: activeModel?.feature_version,
      displayValue: formatFeatureSchema(activeModel?.feature_version),
      variant: "text",
    },
    {
      label: "Trained At",
      value: activeModel?.trained_at,
      displayValue: formatTimestamp(activeModel?.trained_at),
      variant: "time",
    },
    {
      label: "Average Probability",
      value: activeModel?.average_probability,
      displayValue: formatProbabilityPercent(activeModel?.average_probability),
      variant: "stat",
    },
    {
      label: "Predictions",
      value: activeModel?.predictions_total ?? 0,
      displayValue: formatMetric(activeModel?.predictions_total ?? 0),
      variant: "stat",
    },
  ]);

  renderMiniBars(activeTopFeatures, activeModel?.top_features || [], {
    emptyLabel: "Train and activate a model to see feature influence.",
    formatter: (value) => Number(value || 0).toFixed(3),
  });

  renderMetricCards(activeModelAnalytics, [
    { label: "Unknown", value: activeModel?.unknown_total ?? 0, variant: "stat" },
    { label: "Phishing", value: activeModel?.phishing_total ?? 0, variant: "stat" },
    { label: "Benign", value: activeModel?.benign_total ?? 0, variant: "stat" },
    {
      label: "Last Prediction",
      value: activeModel?.last_prediction_utc,
      displayValue: formatTimestamp(activeModel?.last_prediction_utc),
      variant: "time",
    },
  ]);
}

function renderRuntime(payload) {
  const runtime = payload?.runtime || {};
  const defaults = payload?.training_defaults || {};
  const devices = runtime.devices || [
    { id: "auto", label: "Auto select" },
    { id: "cpu", label: "CPU" },
  ];

  if (deviceInput) {
    const currentValue = deviceInput.value || defaults.device || "auto";
    deviceInput.innerHTML = devices
      .map((device) => `<option value="${escapeHtml(device.id)}">${escapeHtml(device.label)}</option>`)
      .join("");
    deviceInput.value = devices.some((device) => device.id === currentValue) ? currentValue : "auto";
  }

  if (!runtimeDefaultsInitialized) {
    if (epochsInput && defaults.epochs != null) epochsInput.value = String(defaults.epochs);
    if (batchSizeInput && defaults.batch_size != null) batchSizeInput.value = String(defaults.batch_size);
    if (learningRateInput && defaults.learning_rate != null) learningRateInput.value = String(defaults.learning_rate);
    if (testSizeInput && defaults.test_size != null) testSizeInput.value = String(defaults.test_size);
    if (validationSplitInput && defaults.validation_split != null) {
      validationSplitInput.value = String(defaults.validation_split);
    }
    if (dropoutRateInput && defaults.dropout_rate != null) dropoutRateInput.value = String(defaults.dropout_rate);
    if (hiddenUnitsInput && Array.isArray(defaults.hidden_units)) hiddenUnitsInput.value = defaults.hidden_units.join(",");
    if (earlyStoppingInput && defaults.early_stopping_patience != null) {
      earlyStoppingInput.value = String(defaults.early_stopping_patience);
    }
    if (thresholdInput && defaults.classification_threshold != null) {
      thresholdInput.value = String(defaults.classification_threshold);
    }
    if (randomStateInput && defaults.random_state != null) randomStateInput.value = String(defaults.random_state);
    if (activateModelInput && defaults.activate_after_training != null) {
      activateModelInput.checked = Boolean(defaults.activate_after_training);
    }
    runtimeDefaultsInitialized = true;
  }

  if (!runtime.available) {
    mlRuntimeSummary.textContent = "TensorFlow is not installed yet. Training will fail until the dependency is available.";
    if (mlRuntimeNote) {
      mlRuntimeNote.textContent = runtime.error || "Install TensorFlow in the same environment as the app server before starting a run.";
    }
    return;
  }
  const gpuSummary = runtime.gpus?.length ? `${runtime.gpus.length} GPU(s) detected` : "No GPU detected";
  const warning = Array.isArray(runtime.warnings) && runtime.warnings.length ? ` • ${runtime.warnings[0]}` : "";
  mlRuntimeSummary.textContent = `TensorFlow ${runtime.version || "available"} • ${gpuSummary}${warning}`;
  if (mlRuntimeNote) {
    mlRuntimeNote.textContent = runtime.gpus?.length
      ? "A detected GPU can be targeted directly from the training device control."
      : "Manual GPU choices are still available, but this host currently looks CPU-bound.";
  }
}

function renderRecentRows(rows) {
  if (!rows || rows.length === 0) {
    mlRecentRows.className = "recent-stream empty-state";
    mlRecentRows.textContent = "No rows processed yet.";
    return;
  }
  mlRecentRows.className = "recent-stream";
  mlRecentRows.innerHTML = rows
    .map(
      (row) => `
        <article class="recent-row">
          <div>
            <strong>${escapeHtml(row.url || "Unknown URL")}</strong>
            <span>Row ${escapeHtml(String(row.index || "-"))}</span>
          </div>
          <span class="status-pill ${row.skipped_rows ? "warn" : "ok"}">
            Usable ${escapeHtml(String(row.usable_rows || 0))}
          </span>
        </article>
      `,
    )
    .join("");
}

function renderRecentRuns(runs) {
  if (!runs || runs.length === 0) {
    mlRecentRuns.className = "recent-stream empty-state";
    mlRecentRuns.textContent = "No saved runs yet.";
    return;
  }
  mlRecentRuns.className = "recent-stream";
  mlRecentRuns.innerHTML = runs
    .map((run) => {
      const tone = toneForStatus(run.status);
      return `
        <article class="recent-row">
          <div>
            <strong>${escapeHtml(run.model_version || run.input_filename || "Untitled run")}</strong>
            <span>${escapeHtml(run.input_filename || "CSV upload")} • F1 ${escapeHtml(formatMetric(run.f1))}</span>
          </div>
          <span class="status-pill ${tone}">${escapeHtml(run.status)}</span>
        </article>
      `;
    })
    .join("");
}

function topFeatureLabel(run) {
  const first = (run?.feature_importance || [])[0];
  if (!first?.feature) return "n/a";
  return `${humanizeIdentifier(first.feature)} (${Number(first.importance || 0).toFixed(3)})`;
}

function renderRegistryHighlights(models) {
  if (!models || models.length === 0) {
    mlRegistryHighlights.className = "summary-metric-grid empty-state";
    mlRegistryHighlights.textContent = "No saved models in the registry yet.";
    return;
  }

  const byMetric = (metric) =>
    [...models]
      .filter((model) => Number.isFinite(Number(model?.[metric])))
      .sort((a, b) => Number(b?.[metric] || 0) - Number(a?.[metric] || 0))[0];

  const bestF1 = byMetric("f1");
  const bestRocAuc = byMetric("roc_auc");
  const lightest = [...models]
    .filter((model) => Number.isFinite(Number(model?.model_summary?.total_params)))
    .sort((a, b) => Number(a?.model_summary?.total_params || 0) - Number(b?.model_summary?.total_params || 0))[0];

  const cards = [
    {
      label: "Saved Models",
      value: models.length,
      meta: models[0]?.completed_at ? `Latest ${formatTimestamp(models[0].completed_at)}` : "Registry-backed history",
      variant: "stat",
    },
    {
      label: "Best F1",
      value: bestF1 ? formatMetric(bestF1.f1) : "n/a",
      meta: bestF1 ? `${formatModelVersion(bestF1.model_version)} • ${bestF1.input_filename || "CSV upload"}` : "No completed model",
      variant: "text",
    },
    {
      label: "Best ROC AUC",
      value: bestRocAuc ? formatMetric(bestRocAuc.roc_auc) : "n/a",
      meta: bestRocAuc ? `${formatModelVersion(bestRocAuc.model_version)} • ${bestRocAuc?.model_summary?.epochs_trained ?? "n/a"} epochs` : "No completed model",
      variant: "text",
    },
    {
      label: "Smallest Model",
      value: lightest ? `${lightest?.model_summary?.total_params ?? "n/a"} params` : "n/a",
      meta: lightest ? `${formatModelVersion(lightest.model_version)} • ${lightest?.model_summary?.resolved_device ?? "n/a"}` : "No completed model",
      variant: "text",
    },
  ];

  mlRegistryHighlights.className = "summary-metric-grid";
  renderMetricCards(mlRegistryHighlights, cards);
}

function renderModelRegistry(models) {
  if (!models || models.length === 0) {
    mlRegistryCompare.className = "table-wrap empty-state";
    mlRegistryCompare.textContent = "No saved model registry entries yet.";
    return;
  }

  mlRegistryCompare.className = "table-wrap";
  mlRegistryCompare.innerHTML = `
    <table class="report-table compare-table">
      <thead>
        <tr>
          <th>Params</th>
          <th>Completed</th>
          <th>Accuracy</th>
          <th>F1</th>
          <th>ROC AUC</th>
          <th>Model</th>
          <th>Rows</th>
          <th>Top Feature</th>
        </tr>
      </thead>
      <tbody>
        ${models
          .slice(0, 12)
          .map(
            (run) => `
              <tr>
                <td class="table-url">
                  <strong>${escapeHtml(formatModelVersion(run.model_version || run.input_filename || "Untitled model"))}</strong>
                  <small>${escapeHtml(run.input_filename || "CSV upload")} • ${escapeHtml(formatModelType(run.model_type))}${run.activated ? " • Active at train time" : ""}</small>
                </td>
                <td>${escapeHtml(formatTimestamp(run.completed_at || run.trained_at || run.created_at))}</td>
                <td>${escapeHtml(formatMetric(run.accuracy))}</td>
                <td>${escapeHtml(formatMetric(run.f1))}</td>
                <td>${escapeHtml(formatMetric(run.roc_auc))}</td>
                <td>
                  <strong>${escapeHtml(String(run?.model_summary?.total_params ?? "n/a"))}</strong>
                  <small>${escapeHtml(String((Array.isArray(run?.model_summary?.hidden_units) ? run.model_summary.hidden_units : []).join(" / ") || "n/a"))}</small>
                </td>
                <td>
                  <strong>${escapeHtml(String(run.usable_rows ?? "n/a"))}</strong>
                  <small>${escapeHtml(String(run.train_rows ?? "n/a"))} train / ${escapeHtml(String(run.test_rows ?? "n/a"))} test</small>
                </td>
                <td class="compare-feature-cell">${escapeHtml(topFeatureLabel(run))}</td>
              </tr>
            `,
          )
          .join("")}
      </tbody>
    </table>
  `;
}

function renderMlJob(job) {
  const tone = toneForStatus(job.status);
  mlJobBadge.textContent = job.status === "completed" ? "Report Ready" : job.status;
  mlJobBadge.className = `summary-state ${tone}`;
  mlProgressFill.style.width = `${job.progress_percent || 0}%`;
  mlProgressText.textContent = `${job.processed_rows || 0} of ${job.total_rows || 0} URLs processed`;
  mlProgressPercent.textContent = `${Number(job.progress_percent || 0).toFixed(1)}%`;
  mlProcessedCount.textContent = String(job.processed_rows || 0);
  mlUsableCount.textContent = String(job.usable_rows || 0);
  mlSkippedCount.textContent = String(job.skipped_rows || 0);
  mlCurrentPhase.textContent = job.current_phase || "queued";
  mlCurrentUrl.textContent = job.current_url || "No active URL";
  renderCheckList(job.check_states || {});
  renderRecentRows(job.recent_rows || []);

  if (job.status === "failed") {
    setTrainingControlsDisabled(false);
    setBusy(false);
    stopLoadingDetails();
    setStatus(job.message || "ML job failed.", "danger", "Review the dataset, skipped rows, and hyperparameters before running another experiment.");
  } else if (job.status === "completed") {
    setTrainingControlsDisabled(false);
    setBusy(false);
    stopLoadingDetails();
    setStatus(job.message || "ML job completed.", "ok", "The experiment report is ready. Compare train and test behavior before activating any conclusion.");
  } else {
    setTrainingControlsDisabled(true);
    setBusy(true, "Training in progress...");
    setStatus(job.message || "ML job in progress...", "warn", loadingDetails[1]);
  }
}

function renderConfusionMatrix(target, matrix) {
  const cells = [
    ["True Positives", matrix?.tp ?? 0, "danger"],
    ["False Positives", matrix?.fp ?? 0, "warn"],
    ["False Negatives", matrix?.fn ?? 0, "warn"],
    ["True Negatives", matrix?.tn ?? 0, "ok"],
  ];
  target.innerHTML = cells
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

function destroyChart(key) {
  if (charts[key]) {
    charts[key].destroy();
    delete charts[key];
  }
}

function setMlActiveTab(tabId) {
  mlTabButtons.forEach((button) => {
    button.classList.toggle("is-active", button.dataset.mlTab === tabId);
  });
  mlTabPanels.forEach((panel) => {
    panel.classList.toggle("is-active", panel.dataset.mlPanel === tabId);
  });
}

function buildChartOptions(extra = {}) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: chartTheme.text,
          boxWidth: 12,
          boxHeight: 12,
          useBorderRadius: true,
          borderRadius: 4,
          font: {
            family: "Instrument Sans, Segoe UI, sans-serif",
            weight: "600",
          },
        },
      },
      tooltip: {
        backgroundColor: "rgba(15, 23, 42, 0.92)",
        titleColor: "#f8fafc",
        bodyColor: "#e2e8f0",
        padding: 12,
        cornerRadius: 12,
      },
    },
    scales: {
      x: {
        ticks: { color: chartTheme.mutedText },
        grid: { color: chartTheme.grid, drawBorder: false },
      },
      y: {
        ticks: { color: chartTheme.mutedText },
        grid: { color: chartTheme.grid, drawBorder: false },
      },
    },
    ...extra,
  };
}

function linearUnitScale(axisTitle) {
  return {
    type: "linear",
    min: 0,
    max: 1,
    ticks: {
      color: chartTheme.mutedText,
      callback: (value) => Number(value).toFixed(1),
    },
    grid: { color: chartTheme.grid, drawBorder: false },
    title: {
      display: true,
      text: axisTitle,
      color: chartTheme.mutedText,
    },
  };
}

function renderMetricsChart(report) {
  const canvas = document.getElementById("ml-metrics-chart");
  destroyChart("metrics");
  if (!window.Chart || !report?.splits) return;
  charts.metrics = new Chart(canvas, {
    type: "bar",
    data: {
      labels: ["Accuracy", "Precision", "Recall", "F1", "ROC AUC"],
      datasets: [
        {
          label: "Train",
          data: [
            report.splits.train.accuracy,
            report.splits.train.precision,
            report.splits.train.recall,
            report.splits.train.f1,
            report.splits.train.roc_auc,
          ],
          backgroundColor: chartTheme.primary,
        },
        {
          label: "Validation",
          data: [
            report.splits.validation?.accuracy,
            report.splits.validation?.precision,
            report.splits.validation?.recall,
            report.splits.validation?.f1,
            report.splits.validation?.roc_auc,
          ],
          backgroundColor: chartTheme.warning,
        },
        {
          label: "Test",
          data: [
            report.splits.test.accuracy,
            report.splits.test.precision,
            report.splits.test.recall,
            report.splits.test.f1,
            report.splits.test.roc_auc,
          ],
          backgroundColor: chartTheme.success,
        },
      ],
    },
    options: buildChartOptions({
      scales: {
        x: {
          ticks: { color: chartTheme.mutedText },
          grid: { display: false, drawBorder: false },
        },
        y: {
          beginAtZero: true,
          suggestedMax: 1,
          ticks: { color: chartTheme.mutedText },
          grid: { color: chartTheme.grid, drawBorder: false },
        },
      },
    }),
  });
}

function renderLossChart(report) {
  const canvas = document.getElementById("ml-loss-chart");
  destroyChart("loss");
  const history = report?.training_history || {};
  const epochs = history.epoch || [];
  if (!window.Chart || epochs.length === 0) return;
  charts.loss = new Chart(canvas, {
    type: "line",
    data: {
      labels: epochs,
      datasets: [
        {
          label: "Train Loss",
          data: history.loss || [],
          borderColor: chartTheme.primary,
          backgroundColor: "rgba(34, 96, 201, 0.12)",
          tension: 0.2,
          pointRadius: 2,
          fill: false,
        },
        {
          label: "Validation Loss",
          data: history.val_loss || [],
          borderColor: chartTheme.danger,
          backgroundColor: "rgba(197, 58, 58, 0.12)",
          tension: 0.2,
          pointRadius: 2,
          fill: false,
        },
      ],
    },
    options: buildChartOptions({
      scales: {
        x: {
          ticks: { color: chartTheme.mutedText },
          grid: { display: false, drawBorder: false },
          title: { display: true, text: "Epoch", color: chartTheme.mutedText },
        },
        y: {
          beginAtZero: true,
          ticks: { color: chartTheme.mutedText },
          grid: { color: chartTheme.grid, drawBorder: false },
          title: { display: true, text: "Loss", color: chartTheme.mutedText },
        },
      },
    }),
  });
}

function renderAccuracyChart(report) {
  const canvas = document.getElementById("ml-accuracy-chart");
  destroyChart("accuracyHistory");
  const history = report?.training_history || {};
  const epochs = history.epoch || [];
  if (!window.Chart || epochs.length === 0) return;
  charts.accuracyHistory = new Chart(canvas, {
    type: "line",
    data: {
      labels: epochs,
      datasets: [
        {
          label: "Train Accuracy",
          data: history.accuracy || [],
          borderColor: chartTheme.success,
          backgroundColor: "rgba(19, 155, 103, 0.12)",
          tension: 0.2,
          pointRadius: 2,
          fill: false,
        },
        {
          label: "Validation Accuracy",
          data: history.val_accuracy || [],
          borderColor: chartTheme.violet,
          backgroundColor: "rgba(103, 80, 214, 0.12)",
          tension: 0.2,
          pointRadius: 2,
          fill: false,
        },
      ],
    },
    options: buildChartOptions({
      scales: {
        x: {
          ticks: { color: chartTheme.mutedText },
          grid: { display: false, drawBorder: false },
          title: { display: true, text: "Epoch", color: chartTheme.mutedText },
        },
        y: {
          beginAtZero: true,
          suggestedMax: 1,
          ticks: { color: chartTheme.mutedText },
          grid: { color: chartTheme.grid, drawBorder: false },
          title: { display: true, text: "Accuracy", color: chartTheme.mutedText },
        },
      },
    }),
  });
}

function renderDistributionChart(report) {
  const canvas = document.getElementById("ml-distribution-chart");
  destroyChart("distribution");
  const bins = report?.probability_distribution || [];
  if (!window.Chart || bins.length === 0) return;
  charts.distribution = new Chart(canvas, {
    type: "bar",
    data: {
      labels: bins.map((bin) => bin.label),
      datasets: [
        {
          label: "Legitimate",
          data: bins.map((bin) => bin.legitimate),
          backgroundColor: chartTheme.success,
        },
        {
          label: "Phishing",
          data: bins.map((bin) => bin.phishing),
          backgroundColor: chartTheme.danger,
        },
      ],
    },
    options: buildChartOptions({
      scales: {
        x: {
          stacked: true,
          ticks: { color: chartTheme.mutedText },
          grid: { display: false, drawBorder: false },
        },
        y: {
          stacked: true,
          beginAtZero: true,
          ticks: { color: chartTheme.mutedText },
          grid: { color: chartTheme.grid, drawBorder: false },
        },
      },
    }),
  });
}

function renderFeatureChart(report) {
  const canvas = document.getElementById("ml-feature-chart");
  destroyChart("features");
  const items = (report?.feature_importance || []).slice(0, 10).reverse();
  if (!window.Chart || items.length === 0) return;
  charts.features = new Chart(canvas, {
    type: "bar",
    data: {
      labels: items.map((item) => item.feature),
      datasets: [
        {
          label: "Importance",
          data: items.map((item) => item.importance),
          backgroundColor: chartTheme.primary,
        },
      ],
    },
    options: buildChartOptions({
      indexAxis: "y",
      scales: {
        x: {
          beginAtZero: true,
          ticks: { color: chartTheme.mutedText },
          grid: { color: chartTheme.grid, drawBorder: false },
        },
        y: {
          ticks: { color: chartTheme.text },
          grid: { display: false, drawBorder: false },
        },
      },
    }),
  });
}

function renderRocChart(report) {
  const canvas = document.getElementById("ml-roc-chart");
  destroyChart("roc");
  const curve = report?.visualizations?.roc_curve;
  const points = curve?.points || [];
  if (!window.Chart || points.length === 0) return;
  charts.roc = new Chart(canvas, {
    type: "line",
    data: {
      datasets: [
        {
          label: `ROC AUC ${formatMetric(curve?.auc)}`,
          data: points.map((point) => ({
            x: point.false_positive_rate,
            y: point.true_positive_rate,
          })),
          borderColor: chartTheme.danger,
          backgroundColor: "rgba(197, 58, 58, 0.18)",
          borderWidth: 2.2,
          pointRadius: 2,
          pointHoverRadius: 4,
          tension: 0.16,
        },
        {
          label: "Random Baseline",
          data: [
            { x: 0, y: 0 },
            { x: 1, y: 1 },
          ],
          borderColor: chartTheme.mutedText,
          borderDash: [6, 6],
          pointRadius: 0,
        },
      ],
    },
    options: buildChartOptions({
      parsing: false,
      scales: {
        x: linearUnitScale("False Positive Rate"),
        y: linearUnitScale("True Positive Rate"),
      },
    }),
  });
}

function renderPrecisionRecallChart(report) {
  const canvas = document.getElementById("ml-pr-chart");
  destroyChart("precisionRecall");
  const curve = report?.visualizations?.precision_recall_curve;
  const points = curve?.points || [];
  if (!window.Chart || points.length === 0) return;
  charts.precisionRecall = new Chart(canvas, {
    type: "line",
    data: {
      datasets: [
        {
          label: `PR AUC ${formatMetric(curve?.auc)}`,
          data: points.map((point) => ({
            x: point.recall,
            y: point.precision,
          })),
          borderColor: chartTheme.violet,
          backgroundColor: "rgba(103, 80, 214, 0.16)",
          borderWidth: 2.2,
          pointRadius: 2,
          pointHoverRadius: 4,
          tension: 0.18,
        },
      ],
    },
    options: buildChartOptions({
      parsing: false,
      scales: {
        x: linearUnitScale("Recall"),
        y: linearUnitScale("Precision"),
      },
    }),
  });
}

function renderThresholdChart(report) {
  const canvas = document.getElementById("ml-threshold-chart");
  destroyChart("threshold");
  const points = report?.visualizations?.threshold_analysis || [];
  if (!window.Chart || points.length === 0) return;
  charts.threshold = new Chart(canvas, {
    type: "line",
    data: {
      datasets: [
        {
          label: "Precision",
          data: points.map((point) => ({ x: point.threshold, y: point.precision })),
          borderColor: chartTheme.primary,
          backgroundColor: "rgba(34, 96, 201, 0.14)",
          tension: 0.2,
          pointRadius: 1.8,
        },
        {
          label: "Recall",
          data: points.map((point) => ({ x: point.threshold, y: point.recall })),
          borderColor: chartTheme.success,
          backgroundColor: "rgba(19, 155, 103, 0.14)",
          tension: 0.2,
          pointRadius: 1.8,
        },
        {
          label: "F1",
          data: points.map((point) => ({ x: point.threshold, y: point.f1 })),
          borderColor: chartTheme.danger,
          backgroundColor: "rgba(197, 58, 58, 0.14)",
          tension: 0.2,
          pointRadius: 1.8,
        },
        {
          label: "Specificity",
          data: points.map((point) => ({ x: point.threshold, y: point.specificity })),
          borderColor: chartTheme.warning,
          backgroundColor: "rgba(180, 118, 21, 0.12)",
          tension: 0.2,
          pointRadius: 1.8,
        },
      ],
    },
    options: buildChartOptions({
      parsing: false,
      scales: {
        x: linearUnitScale("Threshold"),
        y: linearUnitScale("Metric Value"),
      },
    }),
  });
}

function renderCalibrationChart(report) {
  const canvas = document.getElementById("ml-calibration-chart");
  destroyChart("calibration");
  const bins = (report?.visualizations?.calibration_curve?.bins || []).filter(
    (item) => item.avg_confidence != null && item.actual_positive_rate != null,
  );
  if (!window.Chart || bins.length === 0) return;
  charts.calibration = new Chart(canvas, {
    type: "line",
    data: {
      datasets: [
        {
          label: "Ideal Calibration",
          data: [
            { x: 0, y: 0 },
            { x: 1, y: 1 },
          ],
          borderColor: chartTheme.mutedText,
          borderDash: [6, 6],
          pointRadius: 0,
        },
        {
          label: `Observed • Brier ${formatMetric(report?.visualizations?.calibration_curve?.brier_score)}`,
          data: bins.map((item) => ({
            x: item.avg_confidence,
            y: item.actual_positive_rate,
          })),
          borderColor: chartTheme.success,
          backgroundColor: "rgba(19, 155, 103, 0.16)",
          borderWidth: 2.2,
          pointRadius: 3,
          pointHoverRadius: 5,
          tension: 0.15,
        },
      ],
    },
    options: buildChartOptions({
      parsing: false,
      scales: {
        x: linearUnitScale("Average Confidence"),
        y: linearUnitScale("Observed Positive Rate"),
      },
    }),
  });
}

function renderFeatureCumulativeChart(report) {
  const canvas = document.getElementById("ml-feature-cumulative-chart");
  destroyChart("featureCumulative");
  const points = report?.visualizations?.feature_importance_cumulative || [];
  if (!window.Chart || points.length === 0) return;
  charts.featureCumulative = new Chart(canvas, {
    type: "line",
    data: {
      labels: points.map((point) => `#${point.rank}`),
      datasets: [
        {
          label: "Cumulative Importance",
          data: points.map((point) => point.cumulative_importance),
          borderColor: chartTheme.primary,
          backgroundColor: "rgba(34, 96, 201, 0.16)",
          borderWidth: 2.2,
          pointRadius: 2.5,
          pointHoverRadius: 4,
          tension: 0.18,
          fill: true,
        },
      ],
    },
    options: buildChartOptions({
      plugins: {
        tooltip: {
          backgroundColor: "rgba(15, 23, 42, 0.92)",
          titleColor: "#f8fafc",
          bodyColor: "#e2e8f0",
          padding: 12,
          cornerRadius: 12,
          callbacks: {
            title: (items) => {
              const item = points[items[0]?.dataIndex || 0];
              return item?.feature || "Feature";
            },
          },
        },
      },
      scales: {
        x: {
          ticks: { color: chartTheme.mutedText },
          grid: { display: false, drawBorder: false },
          title: {
            display: true,
            text: "Feature Rank",
            color: chartTheme.mutedText,
          },
        },
        y: linearUnitScale("Cumulative Importance"),
      },
    }),
  });
}

function renderErrorAnalysis(report) {
  const mistakes = report?.error_analysis?.hardest_mistakes || [];
  if (mistakes.length === 0) {
    mlErrorAnalysis.className = "recent-stream empty-state";
    mlErrorAnalysis.textContent = "No high-confidence mistakes were recorded on the current test split.";
    return;
  }
  mlErrorAnalysis.className = "recent-stream";
  mlErrorAnalysis.innerHTML = mistakes
    .slice(0, 6)
    .map((item) => {
      const tone = item.predicted_label === "phishing" ? "warn" : "danger";
      const label = item.predicted_label === "phishing" ? "False positive" : "False negative";
      const location = item.host || item.normalized_url || item.url || "Unknown URL";
      return `
        <article class="recent-row">
          <div>
            <strong>${escapeHtml(location)}</strong>
            <span>${escapeHtml(label)} • actual ${escapeHtml(item.actual_label)} • confidence ${escapeHtml(formatProbabilityPercent(item.confidence))}</span>
          </div>
          <span class="status-pill ${tone}">${escapeHtml(label)}</span>
        </article>
      `;
    })
    .join("");
}

function renderArtifactLinks(report) {
  const artifacts = report?.artifacts || {};
  const tensorboard = report?.tensorboard || {};
  const items = [
    {
      label: "History JSON",
      value: artifacts.history_path || "n/a",
      detail: "Saved epoch-by-epoch TensorFlow history for loss and accuracy curves.",
    },
    {
      label: "TensorBoard Log Dir",
      value: artifacts.tensorboard_log_dir || tensorboard.log_dir || "n/a",
      detail: "Keras TensorBoard callback writes the run here.",
    },
    {
      label: "Launch Single Run",
      value: tensorboard.launch_commands?.single_run || "n/a",
      detail: "Open this experiment by itself.",
    },
    {
      label: "Compare Runs",
      value: tensorboard.launch_commands?.compare_runs || "n/a",
      detail: "Point TensorBoard at all saved run directories.",
    },
  ];
  mlArtifactLinks.className = "artifact-grid";
  mlArtifactLinks.innerHTML = items
    .map(
      (item) => `
        <article class="artifact-card">
          <span class="metric-label">${escapeHtml(item.label)}</span>
          <strong>${escapeHtml(item.value)}</strong>
          <p class="hint">${escapeHtml(item.detail)}</p>
        </article>
      `,
    )
    .join("");
}

function renderHyperparameters(params) {
  const items = Object.entries(params || {}).map(([key, value]) => ({
    feature: key.replaceAll("_", " "),
    importance: typeof value === "boolean" ? (value ? 1 : 0) : Number(value || 0),
    rawValue: value,
  }));
  if (items.length === 0) {
    mlHyperparameters.className = "mini-bars empty-state";
    mlHyperparameters.textContent = "No completed run yet.";
    return;
  }
  mlHyperparameters.className = "mini-bars";
  mlHyperparameters.innerHTML = Object.entries(params)
    .map(
      ([key, value]) => `
        <div class="mini-bar-row">
          <span>${escapeHtml(key.replaceAll("_", " "))}</span>
          <div class="mini-bar-track">
            <span class="mini-bar-fill primary" style="width:${typeof value === "number" ? Math.min(Math.abs(value) * 10, 100) : 45}%"></span>
          </div>
          <strong>${escapeHtml(String(value))}</strong>
        </div>
      `,
    )
    .join("");
}

function renderMlReport(payload) {
  const report = payload.report;
  const modelSummary = report?.model_summary || {};
  mlReportShell.classList.remove("hidden");
  replayEntrance(mlReportShell);
  renderMetricCards(mlSummaryCards, [
    ["Accuracy", report.summary.accuracy],
    ["Precision", report.summary.precision],
    ["Recall", report.summary.recall],
    ["F1", report.summary.f1],
    ["ROC AUC", report.summary.roc_auc],
    ["Epochs", modelSummary.epochs_trained],
    ["Validation Rows", report.summary.validation_rows],
    ["Test Rows", report.summary.test_rows],
  ]);
  renderConfusionMatrix(mlConfusionMatrix, report.confusion_matrix);
  renderMetricCards(mlTreeSummary, [
    ["Hidden Layers", (modelSummary.hidden_units || []).join(" / ") || "n/a"],
    ["Parameters", modelSummary.total_params],
    ["Device", modelSummary.resolved_device || modelSummary.device || "n/a"],
    ["Activated", report.summary.activated ? "yes" : "no"],
  ]);
  renderHyperparameters(report.hyperparameters);
  renderLossChart(report);
  renderAccuracyChart(report);
  renderMetricsChart(report);
  renderDistributionChart(report);
  renderFeatureChart(report);
  renderErrorAnalysis(report);
  renderArtifactLinks(report);
}

async function loadOverview({ autoloadLatestReport = false } = {}) {
  const payload = await fetchJson("/ml/overview");
  renderActiveModel(payload.active_model);
  renderRuntime(payload);
  const recentJobs = payload.recent_jobs || [];
  const modelRegistry = payload.model_registry || [];
  renderRecentRuns(recentJobs);
  renderRegistryHighlights(modelRegistry);
  renderModelRegistry(modelRegistry);
  if (!autoloadLatestReport) {
    return;
  }

  const latestCompletedJob = recentJobs.find((job) => job.report_ready && job.report_url);
  if (!latestCompletedJob) {
    return;
  }

  if (latestCompletedJob.report_url) {
    await loadReport(latestCompletedJob, { refreshOverview: false, activeTab: "metrics" });
    setStatus("Loaded the most recent completed ML report.", "ok", "This gives you the latest experiment state without starting a new run.");
  }
}

async function loadReport(job, { refreshOverview = true, activeTab = "overview" } = {}) {
  if (!job.report_url) return;
  const payload = await fetchJson(job.report_url);
  renderMlReport(payload);
  setMlActiveTab(activeTab);
  if (refreshOverview) {
    await loadOverview();
  }
}

function schedulePoll(delay = 1200) {
  window.clearTimeout(pollTimer);
  pollTimer = window.setTimeout(pollJob, delay);
}

async function pollJob() {
  if (!activeJobId) return;
  try {
    const job = await fetchJson(`/ml/jobs/${activeJobId}`);
    renderMlJob(job);
    if (job.status === "completed") {
      await loadReport(job, { activeTab: "metrics" });
      return;
    }
    if (job.status === "failed") {
      await loadOverview();
      return;
    }
    schedulePoll();
  } catch (error) {
    stopLoadingDetails();
    setTrainingControlsDisabled(false);
    setBusy(false);
    setStatus(error.message || "Unable to refresh ML job progress.", "danger", "The lab state may be stale until the next successful refresh.");
  }
}

function renderProbeResult(payload) {
  const ml = payload.ml || {};
  const topFeatures = (ml.top_features || [])
    .map((item) => `${item.feature}: ${Number(item.importance || 0).toFixed(3)}`)
    .join(" • ");
  mlProbeResult.className = "probe-result";
  mlProbeResult.innerHTML = `
    <div class="probe-result-header">
      <strong>${escapeHtml(payload.url || "Unknown URL")}</strong>
      <span class="summary-state ${ml.status === "ok" ? (ml.prediction === "phishing" ? "danger" : "ok") : "warn"}">
        ${escapeHtml(ml.prediction || ml.status || "unknown")}
      </span>
    </div>
    <div class="summary-metric-grid compact-grid">
      <article class="summary-metric-card">
        <span class="metric-label">Risk Score</span>
        <strong class="summary-metric-value">${escapeHtml(formatMetric(ml.risk_score || 0))}</strong>
      </article>
      <article class="summary-metric-card">
        <span class="metric-label">Probability</span>
        <strong class="summary-metric-value">${escapeHtml(formatMetric(ml.probability || 0))}</strong>
      </article>
      <article class="summary-metric-card">
        <span class="metric-label">Version</span>
        <strong class="summary-metric-value">${escapeHtml(ml.model_version || "n/a")}</strong>
      </article>
    </div>
    <p class="hint">${escapeHtml(topFeatures || "No model-specific feature importance is available for this probe.")}</p>
    <details class="feature-details">
      <summary>Show extracted features</summary>
      <pre>${escapeHtml(JSON.stringify(payload.features || {}, null, 2))}</pre>
    </details>
  `;
}

mlCsvFileInput.addEventListener("change", async () => {
  const [file] = mlCsvFileInput.files || [];
  if (!file) {
    pendingCsvText = "";
    mlFileSummary.textContent = "Upload a CSV with url and is_phishing.";
    return;
  }
  pendingCsvText = await file.text();
  const lineCount = pendingCsvText.trim() ? pendingCsvText.trim().split(/\r?\n/).length - 1 : 0;
  mlFileSummary.textContent = `${file.name} • ${lineCount} labeled rows • ${(file.size / 1024).toFixed(1)} KB`;
  setStatus("Training dataset loaded.", "muted", "Core settings are ready. Open advanced controls only if you need to shape validation, regularization, or threshold behavior.");
});

mlForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const [file] = mlCsvFileInput.files || [];
  if (!file) {
    setStatus("Choose a labeled CSV before starting a run.", "warn", "The lab expects url and is_phishing columns so it can build features and labels correctly.");
    return;
  }
  try {
    setTrainingControlsDisabled(true);
    setBusy(true, "Starting run...");
    startLoadingDetails();
    const csvContent = pendingCsvText || (await file.text());
    const payload = await fetchJson("/ml/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: file.name,
        csv_content: csvContent,
        device: deviceInput?.value || "auto",
        epochs: Number(epochsInput.value || 0) || null,
        batch_size: Number(batchSizeInput.value || 0) || null,
        learning_rate: Number(learningRateInput.value || 0) || null,
        test_size: Number(testSizeInput.value || 0) || null,
        validation_split: Number(validationSplitInput.value || 0) || null,
        dropout_rate: Number(dropoutRateInput.value || 0) || null,
        hidden_units: hiddenUnitsInput.value
          .split(",")
          .map((value) => Number(value.trim()))
          .filter((value) => Number.isFinite(value) && value > 0),
        early_stopping_patience: Number(earlyStoppingInput.value || 0),
        classification_threshold: Number(thresholdInput.value || 0) || null,
        random_state: Number(randomStateInput.value || 0) || null,
        activate_after_training: activateModelInput.checked,
      }),
    });
    activeJobId = payload.job_id;
    mlReportShell.classList.add("hidden");
    renderMlJob(payload);
    setStatus("TensorFlow run started. Progress will update automatically.", "warn", loadingDetails[0]);
    schedulePoll(500);
  } catch (error) {
    setTrainingControlsDisabled(false);
    setBusy(false);
    stopLoadingDetails();
    setStatus(error.message || "Unable to start ML run.", "danger", "The TensorFlow run did not start cleanly. Review the file, device selection, and training settings, then try again.");
  }
});

mlProbeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = mlProbeUrl.value.trim();
  if (!url) {
    setStatus("Provide a URL to probe the active model.", "warn", "A single probe is useful when you want to inspect how the current model reacts to one suspicious destination.");
    return;
  }
  try {
    setProbeBusy(true);
    setStatus("Running ML-only scan...", "warn", "The probe will return the model verdict, probability, and the strongest extracted features.");
    const payload = await fetchJson("/scan/ml", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    renderProbeResult(payload);
    await loadOverview();
    setStatus("ML probe finished.", "ok", "Use the extracted features to see whether the model is reacting to meaningful phishing cues.");
  } catch (error) {
    setStatus(error.message || "ML probe failed.", "danger", "No trustworthy ML-only result was produced for this URL.");
  } finally {
    setProbeBusy(false);
  }
});

mlTabButtons.forEach((button) => {
  button.addEventListener("click", () => {
    setMlActiveTab(button.dataset.mlTab);
  });
});

renderCheckList();
loadOverview({ autoloadLatestReport: true }).catch((error) => {
  setStatus(error.message || "Unable to load ML overview.", "danger", "The lab could not load its latest model snapshot or recent run history.");
});
