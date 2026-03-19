const form = document.getElementById("scan-form");
const statusEl = document.getElementById("status");
const statusMessageEl = document.getElementById("status-message");
const statusDetailEl = document.getElementById("status-detail");
const summaryEl = document.getElementById("summary");
const detailsEl = document.getElementById("details");
const urlInput = document.getElementById("url-input");
const scanBtn = form.querySelector('button[type="submit"]');

const summaryUrl = document.getElementById("summary-url");
const summaryRisk = document.getElementById("summary-risk");
const summaryBand = document.getElementById("summary-band");
const summaryState = document.getElementById("summary-state");
const summaryGuidance = document.getElementById("summary-guidance");
const summaryAction = document.getElementById("summary-action");
const summaryContrib = document.getElementById("summary-contrib");
const summaryUnknown = document.getElementById("summary-unknown");
const summaryRefresh = document.getElementById("summary-refresh");
const summaryStale = document.getElementById("summary-stale");
const summaryRefreshing = document.getElementById("summary-refreshing");
const summaryRefreshError = document.getElementById("summary-refresh-error");
const detailsJson = document.getElementById("details-json");
const refreshFeedsBtn = document.getElementById("refresh-feeds");
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const loadingDetailSteps = [
  "Normalizing the address so small URL tricks do not slip through.",
  "Checking lexical patterns that often show up in phishing links.",
  "Reviewing certificate and domain-age signals.",
  "Comparing the URL against cached threat-intel feeds.",
];

let loadingDetailTimer = null;
let riskValueAnimationFrame = 0;
let lastStatusSignature = "";
let refreshInFlight = false;

function defaultStatusDetail(tone) {
  if (tone === "danger") {
    return "The last action could not complete cleanly. Review the message above before retrying.";
  }
  if (tone === "warn") {
    return "Slow down and verify the destination manually before anyone opens it.";
  }
  if (tone === "ok") {
    return "No strong phishing indicators surfaced in this pass, but keep normal verification habits.";
  }
  return "Paste a suspicious link to start triage.";
}

function setStatus(message, tone = "muted", detail = defaultStatusDetail(tone)) {
  const signature = `${tone}::${message}::${detail}`;
  if (lastStatusSignature === signature) {
    return;
  }
  lastStatusSignature = signature;
  statusMessageEl.textContent = message;
  statusDetailEl.textContent = detail;
  statusEl.classList.remove("muted", "ok", "caution", "warn", "danger", "status-swap");
  statusEl.classList.add(tone);
  if (tone === "muted") {
    delete statusEl.dataset.tone;
  } else {
    statusEl.dataset.tone = tone;
  }
  requestAnimationFrame(() => statusEl.classList.add("status-swap"));
}

function startLoadingDetails() {
  stopLoadingDetails();
  let stepIndex = 0;
  statusDetailEl.textContent = loadingDetailSteps[stepIndex];
  if (prefersReducedMotion) {
    return;
  }
  loadingDetailTimer = window.setInterval(() => {
    stepIndex = (stepIndex + 1) % loadingDetailSteps.length;
    statusDetailEl.textContent = loadingDetailSteps[stepIndex];
  }, 1350);
}

function stopLoadingDetails() {
  if (loadingDetailTimer) {
    window.clearInterval(loadingDetailTimer);
    loadingDetailTimer = null;
  }
}

function setScanLoading(isLoading) {
  form.classList.toggle("is-scanning", isLoading);
  scanBtn.disabled = isLoading;
  scanBtn.setAttribute("aria-busy", String(isLoading));
  scanBtn.textContent = isLoading ? "Scanning link..." : "Scan Link";
  urlInput.readOnly = isLoading;
  refreshFeedsBtn.disabled = isLoading || refreshInFlight;
  statusEl.classList.toggle("status-loading", isLoading);
  if (isLoading) {
    startLoadingDetails();
  } else {
    stopLoadingDetails();
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getRiskLevel(score) {
  if (score >= 75) {
    return {
      tone: "danger",
      label: "High risk",
      band: "75-100: strong phishing indicators",
      guidance: "This scan found strong phishing indicators. Do not treat the site as safe.",
      action: "Avoid signing in, opening attachments, or entering payment details until the destination is verified by another trusted source.",
      status: "High risk result. Do not trust this site until it is verified.",
    };
  }

  if (score >= 50) {
    return {
      tone: "warn",
      label: "Suspicious",
      band: "50-74: suspicious enough to block trust",
      guidance: "The site looks suspicious enough to require manual verification before you use it.",
      action: "Pause and verify the domain manually. Do not enter credentials or personal information yet.",
      status: "Suspicious result. Verify the site before interacting with it.",
    };
  }

  if (score >= 25) {
    return {
      tone: "caution",
      label: "Use caution",
      band: "25-49: mixed or early warning signals",
      guidance: "Some warning signals were detected, but the scan is not conclusive either way.",
      action: "Proceed carefully only if you expected this site and can confirm the domain independently.",
      status: "Caution advised. Review the signals before trusting this site.",
    };
  }

  return {
    tone: "ok",
    label: "Low apparent risk",
    band: "0-24: no strong signals found",
    guidance: "No strong phishing indicators were found in this scan, but that does not prove the site is safe.",
    action: "Only continue if the address matches what you expected. Stay cautious with logins, downloads, and payment requests.",
    status: "Low apparent risk. Continue carefully, not blindly.",
  };
}

function applyRiskTone(level) {
  summaryEl.dataset.tone = level.tone;
  detailsEl.dataset.tone = level.tone;
  document.body.dataset.riskTone = level.tone;
}

function animateRiskValue(targetScore) {
  window.cancelAnimationFrame(riskValueAnimationFrame);
  const currentValue = Number(summaryRisk.dataset.value || 0);
  const destination = Math.max(0, Math.min(100, Number(targetScore) || 0));
  if (prefersReducedMotion) {
    summaryRisk.textContent = `${Math.round(destination)}`;
    summaryRisk.dataset.value = `${destination}`;
    return;
  }
  const start = performance.now();
  const duration = 760;

  function tick(now) {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 4);
    const nextValue = currentValue + (destination - currentValue) * eased;
    summaryRisk.textContent = `${Math.round(nextValue)}`;
    summaryRisk.dataset.value = `${nextValue}`;
    if (progress < 1) {
      riskValueAnimationFrame = window.requestAnimationFrame(tick);
    }
  }

  riskValueAnimationFrame = window.requestAnimationFrame(tick);
}

function replayEntrance(element) {
  element.classList.remove("panel-enter");
  void element.offsetWidth;
  element.classList.add("panel-enter");
}

function applyRiskMeter(score) {
  const boundedScore = Math.max(0, Math.min(100, Number(score) || 0));
  summaryEl.style.setProperty("--risk-angle", `${boundedScore * 3.6}deg`);
  summaryEl.style.setProperty("--risk-score", boundedScore.toFixed(1));
}

function buildCautionNote(result) {
  const notes = [];
  if ((result.unknown_checks || []).length > 0) {
    notes.push("Some checks could not finish.");
  }
  if (result.feed_freshness?.stale_cache) {
    notes.push("Threat-intel data is using stale cache.");
  }
  return notes.join(" ");
}

function renderTokenList(element, values, emptyLabel, tone = "neutral") {
  element.textContent = "";
  const entries = Array.isArray(values) && values.length > 0 ? values : [emptyLabel];
  entries.forEach((value) => {
    const token = document.createElement("span");
    token.className = `token token-${tone}`;
    token.textContent = value;
    element.appendChild(token);
  });
}

function setBooleanPill(element, value, trueLabel, falseLabel, trueTone, falseTone) {
  const isTrue = Boolean(value);
  element.textContent = isTrue ? trueLabel : falseLabel;
  element.className = `status-pill ${isTrue ? trueTone : falseTone}`;
}

async function scanUrl(url) {
  const response = await fetch("/scan/combined", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Scan failed.");
  }
  return payload;
}

function renderResult(result) {
  const score = Number(result.risk_score || 0);
  const level = getRiskLevel(score);
  const cautionNote = buildCautionNote(result);

  summaryEl.classList.remove("hidden");
  detailsEl.classList.remove("hidden");
  replayEntrance(summaryEl);
  replayEntrance(detailsEl);
  applyRiskTone(level);
  applyRiskMeter(score);

  summaryUrl.textContent = result.url || "-";
  animateRiskValue(score);
  summaryRisk.className = `risk-value ${level.tone}`;
  summaryBand.textContent = level.band;
  summaryState.textContent = level.label;
  summaryState.className = `summary-state ${level.tone}`;
  summaryGuidance.textContent = cautionNote ? `${level.guidance} ${cautionNote}` : level.guidance;
  summaryAction.textContent = level.action;
  renderTokenList(summaryContrib, result.contributing_checks, "No dominant signals", "neutral");
  renderTokenList(summaryUnknown, result.unknown_checks, "All checks returned", "warn");
  summaryRefresh.textContent = result.feed_freshness?.last_refresh_utc || "Unknown";
  setBooleanPill(summaryStale, result.feed_freshness?.stale_cache, "Stale cache", "Current cache", "warn", "ok");
  setBooleanPill(summaryRefreshing, result.feed_freshness?.refresh_in_progress, "Refreshing now", "Idle", "muted", "ok");
  summaryRefreshError.textContent = result.feed_freshness?.refresh_error || "None";

  detailsJson.textContent = JSON.stringify(result.details, null, 2);
  if (cautionNote) {
    setStatus(
      `${level.status} ${cautionNote}`,
      "warn",
      "At least one part of the scan needs manual follow-up before anyone should trust the destination.",
    );
    return;
  }
  setStatus(level.status, level.tone, level.action);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = urlInput.value.trim();
  if (!url) {
    setStatus("Please provide a URL.", "warn", "Try a full link or a bare domain. The scanner will normalize missing protocol when it can.");
    return;
  }
  setScanLoading(true);
  setStatus("Scanning URL for risk signals...", "muted", loadingDetailSteps[0]);
  const scanStart = performance.now();
  try {
    const result = await scanUrl(url);
    renderResult(result);
  } catch (error) {
    setStatus(error.message || "Scan failed.", "danger", "No trustworthy result was produced. Check connectivity, refresh feeds if needed, and try again.");
  } finally {
    const elapsed = performance.now() - scanStart;
    const minVisibleLoadingMs = 550;
    if (elapsed < minVisibleLoadingMs) {
      await sleep(minVisibleLoadingMs - elapsed);
    }
    setScanLoading(false);
  }
});

refreshFeedsBtn.addEventListener("click", async () => {
  if (refreshInFlight) return;
  refreshInFlight = true;
  refreshFeedsBtn.disabled = true;
  refreshFeedsBtn.setAttribute("aria-busy", "true");
  refreshFeedsBtn.textContent = "Refreshing feeds...";
  setStatus("Refreshing feeds...", "muted", "Pulling the latest threat-intel snapshots so new scans use fresher evidence.");
  try {
    const response = await fetch("/feeds/refresh", { method: "POST" });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.detail || "Feed refresh failed.");
    }
    const when = payload.feed_freshness?.last_refresh_utc || "Unknown";
    setStatus(`Feeds refreshed at ${when}.`, "ok", "Fresh intelligence is now ready for the next suspicious link.");
  } catch (error) {
    setStatus(error.message || "Feed refresh failed.", "danger", "The scanner can still run, but threat-intel context may remain older than expected.");
  } finally {
    refreshInFlight = false;
    refreshFeedsBtn.disabled = false;
    refreshFeedsBtn.setAttribute("aria-busy", "false");
    refreshFeedsBtn.textContent = "Refresh Feeds";
  }
});
