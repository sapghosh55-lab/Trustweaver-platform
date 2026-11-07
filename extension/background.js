/**
 * TrustWeaver Shield - Background Service Worker (Manifest V3)
 *
 * Captures the URL of the active tab, executes asynchronous security audits
 * against the backend /scan API, and commands content.js to inject an aggressive,
 * full-screen red warning overlay when critical threats are detected.
 */

const BACKEND_API = "http://localhost:8000";
const SCAN_TIMEOUT_MS = 12000;

// Grade badge colors
const BADGE_COLORS = {
  A: "#10b981", // Emerald
  B: "#06b6d4", // Cyan
  C: "#f59e0b", // Amber
  D: "#f97316", // Orange
  F: "#ef4444", // Crimson
  "?": "#64748b",
};

/**
 * Send fetch request to backend /scan API.
 */
async function queryBackendScan(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

  try {
    const response = await fetch(`${BACKEND_API}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    return { success: true, data };
  } catch (error) {
    clearTimeout(timer);
    console.warn("[TrustWeaver Shield] Scan request failed for:", url, error);
    return { success: false, error: error.message };
  }
}

/**
 * Determine if the scan report indicates a critical threat level.
 */
function isCriticalThreat(report) {
  if (!report) return false;

  const score = report.digital_trust_score ?? 100;
  const verdict = (report.overall_verdict || "").toUpperCase();
  const flags = report.critical_red_flags || [];

  // Critical threat indicators:
  // 1. Digital Trust Score < 40 or Grade F
  // 2. Verdict of MALICIOUS, PHISHING, or DANGEROUS
  // 3. Compromised CA detected (e.g. eMudhra compliance failure)
  // 4. Credential-harvesting brand impersonation
  const certAlerts = report.raw_telemetry?.certificate_validation?.compromised_ca_alerts || [];
  const brandImpersonation = report.raw_telemetry?.phishing_analysis?.brand_impersonation?.detected;

  return (
    score < 40 ||
    verdict === "MALICIOUS" ||
    verdict === "PHISHING" ||
    verdict === "DANGEROUS" ||
    certAlerts.length > 0 ||
    brandImpersonation === true ||
    flags.some((f) => /compromised|broken certificate|impersonation|harvesting/i.test(f))
  );
}

/**
 * Process scanning for an active tab.
 */
async function processTabSecurity(tabId, url, force = false) {
  if (!url || !url.startsWith("http")) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return null;
  }

  const parsed = new URL(url);
  const cacheKey = `scan_${parsed.origin}`;

  // Check cache first
  if (!force) {
    const stored = await chrome.storage.local.get([cacheKey]);
    if (stored[cacheKey]) {
      const { report, timestamp } = stored[cacheKey];
      if (Date.now() - timestamp < 5 * 60 * 1000) {
        handleScanOutcome(tabId, report);
        return report;
      }
    }
  }

  // Set pending indicator
  chrome.action.setBadgeText({ tabId, text: "..." });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#3b82f6" });

  const result = await queryBackendScan(url);

  if (result.success && result.data) {
    const report = result.data;

    // Save to cache
    await chrome.storage.local.set({
      [cacheKey]: { report, timestamp: Date.now() },
    });

    handleScanOutcome(tabId, report);
    return report;
  } else {
    chrome.action.setBadgeText({ tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#64748b" });
    return null;
  }
}

/**
 * Handle scan results: update badge and trigger full-screen warning if critical.
 */
function handleScanOutcome(tabId, report) {
  const grade = report.trust_grade || "?";
  const critical = isCriticalThreat(report);

  // Update extension badge
  chrome.action.setBadgeText({ tabId, text: grade });
  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: critical ? "#ef4444" : (BADGE_COLORS[grade] || "#64748b"),
  });

  // If critical threat, aggressively command content.js to block the page
  if (critical) {
    // 1. Try sending message to content script
    chrome.tabs.sendMessage(tabId, {
      type: "TRIGGER_CRITICAL_BLOCK_OVERLAY",
      report,
    }).catch(() => {
      // 2. If content script is not yet active, inject directly via chrome.scripting
      chrome.scripting.executeScript({
        target: { tabId },
        func: injectFallbackBlocker,
        args: [report],
      }).catch((e) => console.warn("[TrustWeaver] Script injection notice:", e));
    });
  }
}

/**
 * Fallback injector function executed in page context if content.js had not yet initialized.
 */
function injectFallbackBlocker(report) {
  if (window.TrustWeaverBlocker) {
    window.TrustWeaverBlocker.render(report);
  } else {
    window.__pendingTrustWeaverReport = report;
  }
}

// Event: Tab navigation updated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab.url && tab.url.startsWith("http")) {
    processTabSecurity(tabId, tab.url);
  }
});

// Event: User switches tabs
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab && tab.url && tab.url.startsWith("http")) {
      processTabSecurity(activeInfo.tabId, tab.url);
    }
  } catch (err) {
    // Tab closed or inaccessible
  }
});

// Event: Messages from popup.js or content.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_TAB_SCAN") {
    processTabSecurity(message.tabId, message.url, message.force).then((report) => {
      sendResponse({ report });
    });
    return true; // Keep async response channel open
  }
});
