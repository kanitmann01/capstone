const form = document.getElementById("scan-form");
const statusEl = document.getElementById("status");
const statusMessageEl = document.getElementById("status-message");
const statusDetailEl = document.getElementById("status-detail");
const summaryEl = document.getElementById("summary");
const detailsEl = document.getElementById("details");
const urlInput = document.getElementById("url-input");
const scanBtn = form?.querySelector('button[type="submit"]');
const topbarRunDemoBtn = document.getElementById("topbar-run-demo");

const summaryUrl = document.getElementById("summary-url");
const summaryRisk = document.getElementById("summary-risk");
const summaryBand = document.getElementById("summary-band");
const summaryState = document.getElementById("summary-state");
const summaryGuidance = document.getElementById("summary-guidance");
const summaryAction = document.getElementById("summary-action");
const summaryLegacy = document.getElementById("summary-legacy");
const summaryMl = document.getElementById("summary-ml");
const summaryContrib = document.getElementById("summary-contrib");
const summaryUnknown = document.getElementById("summary-unknown");
const summaryHybrid = document.getElementById("summary-hybrid");
const summaryVerdict = document.getElementById("summary-verdict");
const brandValue = document.getElementById("brand-value");
const hostValue = document.getElementById("host-value");
const formValue = document.getElementById("form-value");
const phrasesValue = document.getElementById("phrases-value");
const pathValue = document.getElementById("path-value");
const feedValue = document.getElementById("feed-value");
const explanationValue = document.getElementById("summary-explanation");
const detailsJson = document.getElementById("details-json");
const brandClosenessVerdict = document.getElementById("brand-closeness-verdict");
const brandClosenessCopy = document.getElementById("brand-closeness-copy");
const brandClosenessGraph = document.getElementById("brand-closeness-graph");
const brandClosenessEmpty = document.getElementById("brand-closeness-empty");
const brandClosenessLegend = document.getElementById("brand-closeness-legend");
const brandClosenessThresholdLabel = document.getElementById("brand-closeness-threshold-label");
const targetHost = document.getElementById("target-host");
const formSnippet = document.getElementById("form-snippet");
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

let brandClosenessNetwork = null;

const loadingDetailSteps = [
  "Cleaning up the address and opening a safe snapshot of the page.",
  "Reading visible text, forms, and anything that looks like a login.",
  "Comparing the site to known brands and common risky wording.",
  "Combining scores and evidence into one result for you.",
];

let loadingDetailTimer = null;
let statusSignature = "";
let scoreAnimationFrame = 0;
let scanGeneration = 0;
let activeScanController = null;
const SCAN_TIMEOUT_MS = 180000;
const TOKEN_LIST_CAP = 80;
const TOKEN_TEXT_MAX = 480;

function defaultStatusDetail(tone) {
  if (tone === "danger") {
    return "Do not log in or enter personal data until someone you trust has reviewed this link.";
  }
  if (tone === "warn") {
    return "Treat this as suspicious: double-check the sender and the real company website before you proceed.";
  }
  if (tone === "ok") {
    return "We did not see strong impersonation signals in this pass-still use normal caution online.";
  }
  return "Paste a link above to run a check.";
}

function setStatus(message, tone = "muted", detail = defaultStatusDetail(tone)) {
  const signature = `${tone}::${message}::${detail}`;
  if (signature === statusSignature) {
    return;
  }
  statusSignature = signature;
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
  }, 1200);
}

function stopLoadingDetails() {
  if (loadingDetailTimer) {
    window.clearInterval(loadingDetailTimer);
    loadingDetailTimer = null;
  }
}

function setScanLoading(isLoading) {
  if (!form || !scanBtn || !urlInput) {
    return;
  }
  form.classList.toggle("is-scanning", isLoading);
  scanBtn.disabled = isLoading;
  scanBtn.setAttribute("aria-busy", String(isLoading));
  scanBtn.textContent = isLoading ? "Checking…" : "Analyze link";
  urlInput.readOnly = isLoading;
  urlInput.setAttribute("aria-busy", String(isLoading));
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

function runViewTransition(update) {
  if (prefersReducedMotion || typeof document.startViewTransition !== "function") {
    update();
    return Promise.resolve();
  }
  return document.startViewTransition(update).finished.catch(() => {});
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatFetchErrorMessage(payload, response) {
  const fallback = `Request failed (${response.status}). Try again.`;
  if (!payload || typeof payload !== "object") {
    return fallback;
  }
  const detail = payload.detail;
  if (typeof detail === "string" && detail.trim()) {
    return detail.trim();
  }
  if (Array.isArray(detail)) {
    const parts = detail
      .map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item.msg === "string") {
          const loc = Array.isArray(item.loc) ? item.loc.filter(Boolean).join(".") : "";
          return loc ? `${loc}: ${item.msg}` : item.msg;
        }
        return null;
      })
      .filter(Boolean);
    if (parts.length) {
      return parts.join(" ");
    }
  }
  return fallback;
}

function setTargetHostLine(hostOrUrl) {
  if (!targetHost) return;
  const text = String(hostOrUrl ?? "-");
  targetHost.textContent = "";
  targetHost.appendChild(document.createTextNode("Address: "));
  const span = document.createElement("span");
  span.className = "mono";
  span.textContent = text;
  targetHost.appendChild(span);
}

function renderTokenList(element, values, emptyLabel, tone = "neutral") {
  if (!element) return;
  element.textContent = "";
  let entries = Array.isArray(values) && values.length > 0 ? values.map((v) => String(v)) : [emptyLabel];
  let overflowNote = "";
  if (entries.length > TOKEN_LIST_CAP && entries[0] !== emptyLabel) {
    const extra = entries.length - TOKEN_LIST_CAP;
    entries = entries.slice(0, TOKEN_LIST_CAP);
    overflowNote = `+${extra} more`;
  }
  entries.forEach((value) => {
    const token = document.createElement("span");
    token.className = `token token-${tone}`;
    const slice = value.length > TOKEN_TEXT_MAX ? `${value.slice(0, TOKEN_TEXT_MAX)}…` : value;
    token.textContent = slice;
    token.title = value.length > TOKEN_TEXT_MAX ? value : "";
    element.appendChild(token);
  });
  if (overflowNote) {
    const more = document.createElement("span");
    more.className = "token token-neutral";
    more.textContent = overflowNote;
    element.appendChild(more);
  }
}

function setStatusPill(element, value, yesLabel, noLabel, yesTone, noTone) {
  if (!element) return;
  const isYes = Boolean(value);
  element.textContent = isYes ? yesLabel : noLabel;
  element.className = `status-pill ${isYes ? yesTone : noTone}`;
}

function scoreTone(score) {
  if (score >= 75) {
    return { tone: "danger", label: "High risk", band: "Score 75–100: several strong warning signs" };
  }
  if (score >= 50) {
    return { tone: "warn", label: "Suspicious", band: "Score 50–74: worth a careful second look" };
  }
  if (score >= 25) {
    return { tone: "caution", label: "Use caution", band: "Score 25–49: mixed or weak signals" };
  }
  return { tone: "ok", label: "Lower concern", band: "Score 0–24: no strong warning signs in this check" };
}

function animateScore(targetScore) {
  if (!summaryRisk) return;
  window.cancelAnimationFrame(scoreAnimationFrame);
  const startValue = Number(summaryRisk.dataset.value || 0);
  const endValue = Math.max(0, Math.min(100, Number(targetScore) || 0));
  if (prefersReducedMotion) {
    summaryRisk.textContent = `${Math.round(endValue)}`;
    summaryRisk.dataset.value = `${endValue}`;
    return;
  }
  const start = performance.now();
  const duration = 650;

  function tick(now) {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 4);
    const nextValue = startValue + (endValue - startValue) * eased;
    summaryRisk.textContent = `${Math.round(nextValue)}`;
    summaryRisk.dataset.value = `${nextValue}`;
    if (progress < 1) {
      scoreAnimationFrame = window.requestAnimationFrame(tick);
    }
  }

  scoreAnimationFrame = window.requestAnimationFrame(tick);
}

function explanationFromResult(result) {
  const notes = [];
  const brandSummary = result.brand_impersonation || {};
  if (brandSummary.detected_brand && brandSummary.brand_mismatch) {
    notes.push(`Looks like a ${brandSummary.detected_brand} login clone.`);
  }
  if (brandSummary.free_host_provider) {
    notes.push(`Uses ${brandSummary.free_host_provider}-style free hosting, which scam pages often use.`);
  }
  if ((brandSummary.suspicious_phrase_hits || []).length > 0) {
    notes.push("Uses wording that often appears on fraudulent login pages.");
  }
  if (brandSummary.login_form_present) {
    notes.push("Includes a login form that asks for a password.");
  }
  if (result.override_applied && result.override_reason) {
    notes.push(`We lowered the risk score because ${result.override_reason}.`);
  }
  return notes.join(" ");
}

function scoreText(block) {
  if (!block) return { score: 0, label: "n/a" };
  const rawScore = block.score ?? block.risk_score;
  const fallbackScore = Number.isFinite(Number(block.probability)) ? Number(block.probability) * 100 : 0;
  const score = Number.isFinite(Number(rawScore)) ? Number(rawScore) : fallbackScore;
  const label = block.label || block.prediction || "unknown";
  return { score, label };
}

function formatMaybeScore(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.round(numeric) : "n/a";
}

function screenshotVerdictLabel(rawVerdict) {
  const normalized = String(rawVerdict || "").toLowerCase();
  if (normalized.includes("phish")) return "Likely phishing";
  if (normalized.includes("clean") || normalized.includes("legit") || normalized.includes("safe")) {
    return "Likely legitimate";
  }
  return "Unclear";
}

function showBrandClosenessEmpty(show) {
  if (brandClosenessEmpty) {
    brandClosenessEmpty.classList.toggle("hidden", !show);
  }
  if (brandClosenessGraph) {
    brandClosenessGraph.classList.toggle("hidden", show);
  }
  if (brandClosenessLegend) {
    brandClosenessLegend.classList.toggle("hidden", show);
    brandClosenessLegend.setAttribute("aria-hidden", show ? "true" : "false");
  }
}

function buildBrandClosenessGraphData(parsedRoot, rows, matchedBrand) {
  const rootId = "__scanned_root__";
  const nodes = [
    {
      id: rootId,
      label: parsedRoot || "unknown",
      title: `This link’s domain: ${parsedRoot || "unknown"}`,
      group: "root",
      shape: "dot",
      size: 26,
      font: { size: 16, face: "Instrument Sans, Segoe UI, sans-serif", color: "#0f172a", strokeWidth: 3, strokeColor: "#ffffff" },
      borderWidth: 3,
      color: {
        background: "#2c3e35",
        border: "#1f2f27",
        highlight: { background: "#1f2f27", border: "#1f2f27" },
      },
    },
  ];
  const edges = [];
  rows.forEach((row, index) => {
    const similarity = Math.max(0, Math.min(1, Number(row.similarity_score) || 0));
    const percent = Math.round(similarity * 100);
    const distance = Number(row.levenshtein_distance ?? 0);
    const brand = row.brand || `brand_${index}`;
    const isMatched = Boolean(matchedBrand) && brand === matchedBrand;
    const nodeId = `brand_${brand}_${index}`;
    nodes.push({
      id: nodeId,
      label: row.real_domain || `${brand}.com`,
      title: `${row.real_domain || brand} - ${percent}% similar (edit distance ${distance})`,
      group: isMatched ? "match" : "candidate",
      shape: "box",
      shapeProperties: { borderRadius: 10 },
      margin: 10,
      font: { size: 14, face: "Instrument Sans, Segoe UI, sans-serif", color: isMatched ? "#ffffff" : "#0f172a" },
      borderWidth: isMatched ? 3 : 2,
      color: isMatched
        ? { background: "#b6312a", border: "#8e251f", highlight: { background: "#9e2b24", border: "#7e211c" } }
        : { background: "#e0eee8", border: "#4c8c74", highlight: { background: "#d4e7de", border: "#3f7964" } },
    });
    edges.push({
      from: rootId,
      to: nodeId,
      value: similarity,
      label: `${percent}%`,
      title: `${percent}% similar | edit distance ${distance} | ${row.match_reason || "nearest brand"}`,
      font: { size: 12, face: "Instrument Sans, Segoe UI, sans-serif", color: isMatched ? "#991b1b" : "#0f172a", strokeWidth: 3, strokeColor: "#ffffff", align: "middle" },
      color: isMatched
        ? { color: "#b6312a", highlight: "#9e2b24", hover: "#9e2b24" }
        : { color: "#6d7a74", highlight: "#4c8c74", hover: "#4c8c74" },
      smooth: { enabled: true, type: "dynamic", roundness: 0.35 },
      dashes: distance === 0,
    });
  });
  return { nodes, edges };
}

function renderBrandClosenessGraph(parsedRoot, rows, matchedBrand) {
  if (!brandClosenessGraph || typeof window.vis === "undefined") return;
  let data;
  try {
    data = buildBrandClosenessGraphData(parsedRoot, rows, matchedBrand);
  } catch (err) {
    console.error("Brand closeness graph data failed:", err);
    showBrandClosenessEmpty(true);
    return;
  }
  const options = {
    autoResize: true,
    interaction: {
      dragNodes: true,
      dragView: false,
      zoomView: false,
      hover: true,
      tooltipDelay: 120,
      selectConnectedEdges: false,
    },
    physics: {
      enabled: true,
      solver: "forceAtlas2Based",
      forceAtlas2Based: { gravitationalConstant: -60, springLength: 130, springConstant: 0.08, avoidOverlap: 0.6 },
      stabilization: { enabled: true, iterations: 220, updateInterval: 25, fit: true },
    },
    nodes: {
      shadow: { enabled: true, size: 10, x: 0, y: 3, color: "rgba(15, 23, 42, 0.2)" },
    },
    edges: {
      arrows: { to: { enabled: false } },
      selectionWidth: 1.5,
      scaling: {
        min: 2,
        max: 10,
        label: { enabled: true, min: 11, max: 14 },
      },
      smooth: { enabled: true, type: "dynamic" },
    },
    layout: { improvedLayout: true },
  };

  try {
    if (brandClosenessNetwork) {
      brandClosenessNetwork.setData(data);
      brandClosenessNetwork.setOptions(options);
    } else {
      brandClosenessNetwork = new window.vis.Network(brandClosenessGraph, data, options);
    }
    brandClosenessNetwork.once("stabilizationIterationsDone", () => {
      if (brandClosenessNetwork) {
        const anim = prefersReducedMotion
          ? { duration: 0 }
          : { duration: 420, easingFunction: "easeInOutQuad" };
        brandClosenessNetwork.fit({ animation: anim });
      }
    });
  } catch (err) {
    console.error("Brand closeness graph render failed:", err);
    showBrandClosenessEmpty(true);
  }
}

function renderBrandCloseness(result) {
  if (!brandClosenessVerdict || !brandClosenessCopy) return;
  const brandRecognition = result.brand_recognition || result.details?.brand_recognition || {};
  const allRows = Array.isArray(brandRecognition.brand_closeness) ? brandRecognition.brand_closeness : [];
  const parsedRoot = brandRecognition.parsed_root || result.details?.host || "unknown";
  const threatType = brandRecognition.threat_type || "none";
  const matchedBrand = brandRecognition.matched_brand || "";
  const isScam = brandRecognition.status === "scam";
  const thresholdFraction = Number(brandRecognition.brand_closeness_threshold);
  const thresholdPercent = Number.isFinite(thresholdFraction)
    ? Math.round(thresholdFraction * 100)
    : 70;
  if (brandClosenessThresholdLabel) {
    brandClosenessThresholdLabel.textContent = `${thresholdPercent}%`;
  }

  brandClosenessVerdict.textContent = isScam
    ? `${threatType.replaceAll("_", " ")}: ${matchedBrand || "brand match"}`
    : (brandRecognition.status === "safe" ? "No close look-alike" : "Brand map unavailable");
  brandClosenessVerdict.className = `status-pill ${isScam ? "danger" : "ok"}`;
  const inventorySize = Number(brandRecognition.brand_inventory_size) || 0;
  const inventorySuffix = inventorySize > 0 ? ` We compared this domain to ${inventorySize} known brands.` : "";
  const safeRoot = escapeHtml(parsedRoot);
  const safePct = escapeHtml(String(thresholdPercent));
  const suffixEsc = escapeHtml(inventorySuffix);
  brandClosenessCopy.innerHTML = isScam
    ? `The domain <strong>${safeRoot}</strong> is similar enough to a protected brand that you should treat it as high risk until verified. Only brands above <strong>${safePct}%</strong> similarity are shown on the map.${suffixEsc}`
    : `The domain <strong>${safeRoot}</strong> did not look enough like a protected brand to trigger a spoofing alert. Only brands above <strong>${safePct}%</strong> similarity are shown on the map.${suffixEsc}`;

  const graphRows = allRows.filter((row) => {
    const similarity = Number(row.similarity_score) || 0;
    const isMatched = matchedBrand && row.brand === matchedBrand;
    const isPreserved = row.match_reason === "exact_root_match" || row.match_reason === "deceptive_subdomain_match";
    return similarity >= thresholdFraction || isMatched || isPreserved;
  });

  if (graphRows.length === 0) {
    if (brandClosenessNetwork) {
      brandClosenessNetwork.setData({ nodes: [], edges: [] });
    }
    showBrandClosenessEmpty(true);
    return;
  }

  showBrandClosenessEmpty(false);
  renderBrandClosenessGraph(parsedRoot, graphRows, matchedBrand);
}

function renderResult(result) {
  const fasttext = result.fasttext || {};
  const rules = result.rules || {};
  const scores = result.scores || {};
  const unifiedScore = Number(result.risk_score ?? result.hybrid_score ?? scores.final ?? rules.risk_score ?? 0);
  const hybridScore = Number(result.hybrid_score ?? scores.final ?? unifiedScore);
  const fasttextScore = scoreText(fasttext).score;
  const fasttextLabel = scoreText(fasttext).label;
  const rulesScore = Number(rules.risk_score ?? 0);
  const rulesLabel = rules.prediction || "unknown";
  const legacyScore = scores.legacy;
  const structuredMlScore = scores.structured_ml;
  const brandRecognitionScore = scores.brand_recognition;
  const tone = scoreTone(unifiedScore);
  const explanation = explanationFromResult(result);
  const brandSummary = result.brand_impersonation || {};
  const finalVerdict = result.prediction || fasttextLabel || "unknown";
  const verdictPill = screenshotVerdictLabel(finalVerdict);

  summaryEl.classList.remove("hidden");
  detailsEl.classList.remove("hidden");
  summaryEl.dataset.tone = tone.tone;
  document.body.dataset.riskTone = tone.tone;

  summaryUrl.textContent = result.url || "-";
  setTargetHostLine(result.details?.host || result.url || "-");
  summaryRisk.textContent = `${Math.round(unifiedScore)}`;
  summaryRisk.dataset.value = `${unifiedScore}`;
  summaryBand.textContent = tone.band;
  summaryState.textContent = tone.label;
  summaryState.className = `summary-state ${tone.tone}`;
  summaryGuidance.textContent = result.override_applied
    ? `The URL-only model suggested ${fasttextLabel} (about ${formatMaybeScore(fasttextScore)} out of 100), but we lowered the risk because this address matches an official brand domain.`
    : `The URL-only model suggests ${fasttextLabel} with a score of about ${formatMaybeScore(fasttextScore)} out of 100.`;
  summaryAction.textContent = result.override_applied
    ? `Trusted-domain override: ${result.override_reason}.`
    : (rulesScore > 0
      ? `Rule-based score: ${Math.round(rulesScore)} out of 100 (${rulesLabel}).`
      : "The rule-based checks did not find strong structural red flags this time.");
  if (summaryLegacy) {
    summaryLegacy.textContent = Number.isFinite(Number(legacyScore))
      ? `Older combined score: ${formatMaybeScore(legacyScore)} out of 100.`
      : "No older combined score was returned for this check.";
  }
  if (summaryMl) {
    summaryMl.textContent = Number.isFinite(Number(structuredMlScore))
      ? `Numeric model score: ${formatMaybeScore(structuredMlScore)} out of 100. Brand-similarity score: ${formatMaybeScore(brandRecognitionScore)} out of 100.`
      : `Numeric model not available. Brand-similarity score: ${formatMaybeScore(brandRecognitionScore)} out of 100.`;
  }
  summaryHybrid.textContent = `Overall score: ${Math.round(result.override_applied ? 0 : unifiedScore)}`;
  summaryHybrid.className = `status-pill ${tone.tone}`;
  summaryVerdict.textContent = verdictPill;
  summaryVerdict.className = `status-pill ${tone.tone}`;

  brandValue.textContent = brandSummary.detected_brand || "No brand detected";
  hostValue.textContent = brandSummary.free_host_provider
    ? `${brandSummary.free_host_provider} hosting`
    : (result.details?.host || "Host unknown");
  formValue.textContent = brandSummary.login_form_present
    ? `${brandSummary.password_field_count || 0} password field(s) on the page`
    : "No login form with a password field";
  pathValue.textContent = brandSummary.brand_path_match
    ? "The web address path contains a brand-like name"
    : "No obvious brand name in the path";
  if (feedValue) {
    feedValue.textContent = result.feed_freshness?.last_refresh_utc
      ? `Threat list last updated: ${result.feed_freshness.last_refresh_utc}`
      : (result.feed_freshness?.stale_cache ? "Threat list cache is out of date" : "No threat-list timestamp for this check");
  }
  explanationValue.textContent = explanation || "No short plain-language summary was available—see the fields below.";
  if (formSnippet) {
    const host = result.details?.host || "unknown.host";
    const action = result.details?.form_action_domains?.[0] || `https://${host}/post`;
    formSnippet.textContent = `<form action="${action}" method="POST">\n  <input type="text" name="username" placeholder="username" />\n  <input type="password" name="password" />\n</form>`;
  }
  renderTokenList(
    phrasesValue,
    brandSummary.suspicious_phrase_hits || result.details?.suspicious_phrase_hits,
    "No suspicious phrases found",
    "warn",
  );
  renderTokenList(summaryContrib, result.contributing_checks, "No single check drove the score", "neutral");
  renderTokenList(summaryUnknown, result.unknown_checks, "No inconclusive checks", "warn");
  renderBrandCloseness(result);

  animateScore(unifiedScore);
  setStatus(
    `${tone.label}. ${result.override_applied ? "A trusted brand domain lowered the automated score." : ""} ${explanation || "See the sections below for specifics."}`.trim(),
    tone.tone,
    explanation || (result.override_applied ? "Official brand domain match." : tone.band),
  );
  detailsJson.textContent = JSON.stringify(result, null, 2);
}

async function scanUrl(url, { signal: parentSignal } = {}) {
  const controller = new AbortController();
  const { signal } = controller;
  let timedOut = false;
  const timeoutId = window.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, SCAN_TIMEOUT_MS);
  const onParentAbort = () => controller.abort();
  if (parentSignal) {
    if (parentSignal.aborted) {
      controller.abort();
    } else {
      parentSignal.addEventListener("abort", onParentAbort, { once: true });
    }
  }
  try {
    const response = await fetch("/scan/combined", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal,
    });
    const raw = await response.text();
    let payload = {};
    if (raw) {
      try {
        payload = JSON.parse(raw);
      } catch {
        throw new Error("The server sent a response we could not read. Try again later.");
      }
    }
    if (!response.ok) {
      throw new Error(formatFetchErrorMessage(payload, response));
    }
    return payload;
  } catch (err) {
    if (err && err.name === "AbortError") {
      if (timedOut) {
        throw new Error("This check timed out (the page took too long to respond). Try again or use a shorter link.");
      }
      throw new Error("This check was cancelled.");
    }
    throw err;
  } finally {
    window.clearTimeout(timeoutId);
    if (parentSignal) {
      parentSignal.removeEventListener("abort", onParentAbort);
    }
  }
}

function submitScanFromShell() {
  if (!form) return;
  if (urlInput) {
    urlInput.focus();
  }
  form.requestSubmit();
}

if (form) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const url = urlInput.value.trim();
    if (!url) {
      setStatus("Add a web address first.", "warn", "Paste a full link, for example https://example.com/signin.");
      return;
    }
    if (url.length > 8192) {
      setStatus("That link is too long.", "warn", "Use a shorter address (8192 characters max) or paste only the site name.");
      return;
    }
    scanGeneration += 1;
    const generation = scanGeneration;
    if (activeScanController) {
      activeScanController.abort();
    }
    activeScanController = new AbortController();
    const { signal } = activeScanController;
    const scanStart = performance.now();
    await runViewTransition(() => {
      setScanLoading(true);
      setStatus("Checking the link…", "muted", loadingDetailSteps[0]);
    });
    try {
      const result = await scanUrl(url, { signal });
      if (generation !== scanGeneration) {
        return;
      }
      await runViewTransition(() => {
        renderResult(result);
        setScanLoading(false);
      });
    } catch (error) {
      if (generation !== scanGeneration) {
        return;
      }
      const msg = error && error.message ? error.message : "This check could not complete.";
      const isCancelled = msg === "This check was cancelled.";
      await runViewTransition(() => {
        setStatus(
          isCancelled ? "Check stopped." : msg,
          isCancelled ? "muted" : "danger",
          isCancelled
            ? "A newer check was started or the page was left."
            : "Confirm the address is correct and your network is working, then try again.",
        );
        setScanLoading(false);
      });
    } finally {
      if (generation === scanGeneration) {
        activeScanController = null;
      }
      const elapsed = performance.now() - scanStart;
      const minVisibleLoadingMs = 500;
      if (elapsed < minVisibleLoadingMs) {
        await sleep(minVisibleLoadingMs - elapsed);
      }
      if (generation === scanGeneration) {
        setScanLoading(false);
      }
    }
  });
}

if (topbarRunDemoBtn) {
  topbarRunDemoBtn.addEventListener("click", submitScanFromShell);
}
