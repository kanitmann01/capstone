const form = document.getElementById("scan-form");
const statusEl = document.getElementById("status");
const statusMessageEl = document.getElementById("status-message");
const statusDetailEl = document.getElementById("status-detail");
const summaryEl = document.getElementById("summary");
const detailsEl = document.getElementById("details");
const urlInput = document.getElementById("url-input");
const scanBtn = form?.querySelector('button[type="submit"]');

const summaryUrl = document.getElementById("summary-url");
const summaryRisk = document.getElementById("summary-risk");
const summaryBand = document.getElementById("summary-band");
const summaryState = document.getElementById("summary-state");
const summaryGuidance = document.getElementById("summary-guidance");
const summaryAction = document.getElementById("summary-action");
const summaryContrib = document.getElementById("summary-contrib");
const summaryUnknown = document.getElementById("summary-unknown");
const summaryHybrid = document.getElementById("summary-hybrid");
const summaryVerdict = document.getElementById("summary-verdict");
const brandValue = document.getElementById("brand-value");
const hostValue = document.getElementById("host-value");
const formValue = document.getElementById("form-value");
const phrasesValue = document.getElementById("phrases-value");
const pathValue = document.getElementById("path-value");
const explanationValue = document.getElementById("summary-explanation");
const detailsJson = document.getElementById("details-json");
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

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

function renderResult(result) {
  const fasttext = result.fasttext || {};
  const rules = result.rules || {};
  const hybridScore = Number(result.hybrid_score ?? 0);
  const fasttextScore = scoreText(fasttext).score || Number(result.risk_score || 0);
  const fasttextLabel = scoreText(fasttext).label;
  const rulesScore = Number(rules.risk_score ?? 0);
  const rulesLabel = rules.prediction || "unknown";
  const finalScore = Number(result.risk_score ?? hybridScore ?? rulesScore ?? 0);
  const tone = scoreTone(finalScore);
  const explanation = explanationFromResult(result);
  const brandSummary = result.brand_impersonation || {};
  const finalVerdict = result.prediction || fasttextLabel || "unknown";

  summaryEl.classList.remove("hidden");
  detailsEl.classList.remove("hidden");

  summaryUrl.textContent = result.url || "-";
  summaryRisk.textContent = `${Math.round(fasttextScore)}`;
  summaryRisk.dataset.value = `${fasttextScore}`;
  summaryBand.textContent = tone.band;
  summaryState.textContent = tone.label;
  summaryState.className = `summary-state ${tone.tone}`;
  summaryGuidance.textContent = result.override_applied
    ? `FastText predicts ${fasttextLabel} with a score of ${Math.round(fasttextScore)}, but the final verdict is overridden to clean because the site matches an official brand domain.`
    : `FastText predicts ${fasttextLabel} with a score of ${Math.round(fasttextScore)}.`;
  summaryAction.textContent = result.override_applied
    ? `Official domain override applied: ${result.override_reason}.`
    : (rulesScore > 0
      ? `Rules baseline score: ${Math.round(rulesScore)} (${rulesLabel}).`
      : "Rules baseline did not surface strong evidence in this pass.");
  summaryHybrid.textContent = `Hybrid score: ${Math.round(result.override_applied ? 0 : hybridScore)}`;
  summaryHybrid.className = `status-pill ${tone.tone}`;
  summaryVerdict.textContent = finalVerdict;
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
  explanationValue.textContent = explanation || "No strong narrative evidence was extracted.";
  renderTokenList(
    phrasesValue,
    brandSummary.suspicious_phrase_hits || result.details?.suspicious_phrase_hits,
    "No suspicious phrases found",
    "warn",
  );
  renderTokenList(summaryContrib, result.contributing_checks, "No dominant signals", "neutral");
  renderTokenList(summaryUnknown, result.unknown_checks, "All checks returned", "warn");

  animateScore(fasttextScore);
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
