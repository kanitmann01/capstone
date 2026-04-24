const form = document.getElementById("scan-form");
const statusEl = document.getElementById("status");
const statusMessageEl = document.getElementById("status-message");
const statusDetailEl = document.getElementById("status-detail");
const summaryEl = document.getElementById("summary");
const detailsEl = document.getElementById("details");
const urlInput = document.getElementById("url-input");
const scanBtn = form?.querySelector('button[type="submit"]');
const topbarRunDemoBtn = document.getElementById("topbar-run-demo");
const sidebarNewScanBtn = document.getElementById("sidebar-new-scan");

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
  "Normalizing the URL and preparing the page snapshot.",
  "Reading the visible text, forms, and login structure.",
  "Comparing the host, brand name, and suspicious phrases.",
  "Blending FastText, rules, and evidence into the final demo result.",
];

let loadingDetailTimer = null;
let statusSignature = "";
let scoreAnimationFrame = 0;

function defaultStatusDetail(tone) {
  if (tone === "danger") {
    return "The page needs manual review before anyone should trust it.";
  }
  if (tone === "warn") {
    return "The page looks suspicious enough to pause and inspect further.";
  }
  if (tone === "ok") {
    return "The page does not show strong impersonation signals in this pass.";
  }
  return "Paste a suspicious link to start the demo.";
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
  scanBtn.textContent = isLoading ? "Running Demo..." : "Run Demo";
  urlInput.readOnly = isLoading;
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

function renderTokenList(element, values, emptyLabel, tone = "neutral") {
  if (!element) return;
  element.textContent = "";
  const entries = Array.isArray(values) && values.length > 0 ? values : [emptyLabel];
  entries.forEach((value) => {
    const token = document.createElement("span");
    token.className = `token token-${tone}`;
    token.textContent = value;
    element.appendChild(token);
  });
}

function setStatusPill(element, value, yesLabel, noLabel, yesTone, noTone) {
  if (!element) return;
  const isYes = Boolean(value);
  element.textContent = isYes ? yesLabel : noLabel;
  element.className = `status-pill ${isYes ? yesTone : noTone}`;
}

function scoreTone(score) {
  if (score >= 75) return { tone: "danger", label: "High risk", band: "75-100: strong phishing indicators" };
  if (score >= 50) return { tone: "warn", label: "Suspicious", band: "50-74: suspicious enough to review" };
  if (score >= 25) return { tone: "caution", label: "Use caution", band: "25-49: mixed signals" };
  return { tone: "ok", label: "Low apparent risk", band: "0-24: no strong indicators" };
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
    notes.push(`Hosted on ${brandSummary.free_host_provider}-style free infrastructure.`);
  }
  if ((brandSummary.suspicious_phrase_hits || []).length > 0) {
    notes.push("Uses common phishing language.");
  }
  if (brandSummary.login_form_present) {
    notes.push("Contains a login form with password input.");
  }
  if (result.override_applied && result.override_reason) {
    notes.push(`Final decision overridden because of ${result.override_reason}.`);
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
  if (normalized.includes("phish")) return "PHISHING";
  if (normalized.includes("clean") || normalized.includes("legit") || normalized.includes("safe")) return "CLEAN";
  return "UNKNOWN";
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
      title: `Analyzed root: ${parsedRoot || "unknown"}`,
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
  const data = buildBrandClosenessGraphData(parsedRoot, rows, matchedBrand);
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

  if (brandClosenessNetwork) {
    brandClosenessNetwork.setData(data);
    brandClosenessNetwork.setOptions(options);
  } else {
    brandClosenessNetwork = new window.vis.Network(brandClosenessGraph, data, options);
  }
  brandClosenessNetwork.once("stabilizationIterationsDone", () => {
    if (brandClosenessNetwork) {
      brandClosenessNetwork.fit({ animation: { duration: 420, easingFunction: "easeInOutQuad" } });
    }
  });
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
    : (brandRecognition.status === "safe" ? "No close spoof found" : "Unavailable");
  brandClosenessVerdict.className = `status-pill ${isScam ? "danger" : "ok"}`;
  const inventorySize = Number(brandRecognition.brand_inventory_size) || 0;
  const inventorySuffix = inventorySize > 0 ? ` Compared against ${inventorySize} brands.` : "";
  brandClosenessCopy.innerHTML = isScam
    ? `The analyzed root "<strong>${parsedRoot}</strong>" is close enough to a protected brand to require review. Only candidates above the <strong>${thresholdPercent}%</strong> similarity threshold are shown.${inventorySuffix}`
    : `The analyzed root "<strong>${parsedRoot}</strong>" did not cross the brand-spoofing threshold. Only candidates above the <strong>${thresholdPercent}%</strong> similarity threshold are shown.${inventorySuffix}`;

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

  summaryUrl.textContent = result.url || "-";
  if (targetHost) {
    const displayedTarget = result.details?.host || result.url || "-";
    targetHost.innerHTML = `Target: <span class="mono">${displayedTarget}</span>`;
  }
  summaryRisk.textContent = `${Math.round(unifiedScore)}`;
  summaryRisk.dataset.value = `${unifiedScore}`;
  summaryBand.textContent = tone.band;
  summaryState.textContent = tone.label;
  summaryState.className = `summary-state ${tone.tone}`;
  summaryGuidance.textContent = result.override_applied
    ? `FastText predicts ${fasttextLabel} with a score of ${formatMaybeScore(fasttextScore)}, but the final verdict is overridden to clean because the site matches an official brand domain.`
    : `FastText predicts ${fasttextLabel} with a score of ${formatMaybeScore(fasttextScore)}.`;
  summaryAction.textContent = result.override_applied
    ? `Official domain override applied: ${result.override_reason}.`
    : (rulesScore > 0
      ? `Rules baseline score: ${Math.round(rulesScore)} (${rulesLabel}).`
      : "Rules baseline did not surface strong evidence in this pass.");
  if (summaryLegacy) {
    summaryLegacy.textContent = Number.isFinite(Number(legacyScore))
      ? `Legacy weighted score: ${formatMaybeScore(legacyScore)}.`
      : "Legacy checks did not produce an available weighted score.";
  }
  if (summaryMl) {
    summaryMl.textContent = Number.isFinite(Number(structuredMlScore))
      ? `Structured ML score: ${formatMaybeScore(structuredMlScore)}. Brand recognition score: ${formatMaybeScore(brandRecognitionScore)}.`
      : `Structured ML unavailable. Brand recognition score: ${formatMaybeScore(brandRecognitionScore)}.`;
  }
  summaryHybrid.textContent = `Unified score: ${Math.round(result.override_applied ? 0 : unifiedScore)}`;
  summaryHybrid.className = `status-pill ${tone.tone}`;
  summaryVerdict.textContent = verdictPill;
  summaryVerdict.className = `status-pill ${tone.tone}`;

  brandValue.textContent = brandSummary.detected_brand || "No brand identified";
  hostValue.textContent = brandSummary.free_host_provider
    ? `${brandSummary.free_host_provider} host`
    : (result.details?.host || "Unknown host");
  formValue.textContent = brandSummary.login_form_present
    ? `${brandSummary.password_field_count || 0} password field(s)`
    : "No login form detected";
  pathValue.textContent = brandSummary.brand_path_match
    ? "Brand token appears in the path"
    : "No obvious brand/path match";
  if (feedValue) {
    feedValue.textContent = result.feed_freshness?.last_refresh_utc
      ? `Last refresh: ${result.feed_freshness.last_refresh_utc}`
      : (result.feed_freshness?.stale_cache ? "Threat feed cache is stale" : "No feed refresh timestamp");
  }
  explanationValue.textContent = explanation || "No strong narrative evidence was extracted.";
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
  renderTokenList(summaryContrib, result.contributing_checks, "No dominant signals", "neutral");
  renderTokenList(summaryUnknown, result.unknown_checks, "All checks returned", "warn");
  renderBrandCloseness(result);

  animateScore(unifiedScore);
  setStatus(
    `${tone.label}. ${result.override_applied ? "Official domain match overrode the model score." : ""} ${explanation || "Review the evidence cards for details."}`.trim(),
    tone.tone,
    explanation || (result.override_applied ? "Official brand domain match." : tone.band),
  );
  detailsJson.textContent = JSON.stringify(result, null, 2);
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
      setStatus("Please provide a URL.", "warn", "Paste a full URL or a bare domain.");
      return;
    }
    setScanLoading(true);
    setStatus("Running the scan demo...", "muted", loadingDetailSteps[0]);
    const scanStart = performance.now();
    try {
      const result = await scanUrl(url);
      renderResult(result);
    } catch (error) {
      setStatus(
        error.message || "Scan failed.",
        "danger",
        "No trustworthy result was produced. Check connectivity and try again.",
      );
    } finally {
      const elapsed = performance.now() - scanStart;
      const minVisibleLoadingMs = 500;
      if (elapsed < minVisibleLoadingMs) {
        await sleep(minVisibleLoadingMs - elapsed);
      }
      setScanLoading(false);
    }
  });
}

if (topbarRunDemoBtn) {
  topbarRunDemoBtn.addEventListener("click", submitScanFromShell);
}

if (sidebarNewScanBtn) {
  sidebarNewScanBtn.addEventListener("click", submitScanFromShell);
}
