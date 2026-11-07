/**
 * TrustWeaver Shield - Popup Controller
 *
 * Retrieves active tab security audit telemetry from the background service worker
 * and renders a compact HUD displaying the Digital Trust Score, grade badge,
 * component breakdown, and critical forensic flags.
 */

document.addEventListener("DOMContentLoaded", async () => {
  const domainEl = document.getElementById("target-domain");
  const scoreValEl = document.getElementById("score-val");
  const gradeBadgeEl = document.getElementById("grade-badge");
  const verdictTextEl = document.getElementById("verdict-text");
  const ringProgressEl = document.getElementById("ring-progress");
  const phishingValEl = document.getElementById("phishing-val");
  const certValEl = document.getElementById("cert-val");
  const vulnValEl = document.getElementById("vuln-val");
  const flagsSectionEl = document.getElementById("flags-section");
  const flagsListEl = document.getElementById("flags-list");
  const btnDashboard = document.getElementById("btn-dashboard");
  const btnRescan = document.getElementById("btn-rescan");

  const CIRCUMFERENCE = 2 * Math.PI * 52; // ~326.72

  // Get active tab
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!activeTab || !activeTab.url || !activeTab.url.startsWith("http")) {
    domainEl.textContent = "Non-web target page";
    verdictTextEl.textContent = "INACTIVE ON INTERNAL PAGES";
    return;
  }

  const currentUrl = activeTab.url;
  const parsedUrl = new URL(currentUrl);
  domainEl.textContent = parsedUrl.hostname;

  /**
   * Render report into the mini popup HUD.
   */
  function renderReport(report) {
    if (!report) {
      verdictTextEl.textContent = "SCAN OFFLINE / FAILED";
      return;
    }

    const score = report.digital_trust_score ?? 0;
    const grade = report.trust_grade || "?";
    const verdict = (report.overall_verdict || "UNKNOWN").replace(/_/g, " ");

    scoreValEl.textContent = score;
    gradeBadgeEl.textContent = `Grade ${grade}`;
    verdictTextEl.textContent = verdict;

    // Update circular SVG progress
    const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
    ringProgressEl.style.strokeDashoffset = offset;

    // Apply color theme based on score
    let strokeColor = "#10b981"; // Emerald
    let badgeBg = "rgba(16, 185, 129, 0.2)";
    let badgeBorder = "rgba(16, 185, 129, 0.4)";
    let badgeColor = "#34d399";

    if (score >= 90) {
      strokeColor = "#10b981";
      badgeColor = "#34d399";
    } else if (score >= 75) {
      strokeColor = "#06b6d4";
      badgeBg = "rgba(6, 182, 212, 0.2)";
      badgeBorder = "rgba(6, 182, 212, 0.4)";
      badgeColor = "#22d3ee";
    } else if (score >= 60) {
      strokeColor = "#f59e0b";
      badgeBg = "rgba(245, 158, 11, 0.2)";
      badgeBorder = "rgba(245, 158, 11, 0.4)";
      badgeColor = "#fbbf24";
    } else if (score >= 40) {
      strokeColor = "#f97316";
      badgeBg = "rgba(249, 115, 22, 0.2)";
      badgeBorder = "rgba(249, 115, 22, 0.4)";
      badgeColor = "#fb923c";
    } else {
      strokeColor = "#ef4444";
      badgeBg = "rgba(239, 68, 68, 0.2)";
      badgeBorder = "rgba(239, 68, 68, 0.4)";
      badgeColor = "#f87171";
    }

    ringProgressEl.style.stroke = strokeColor;
    gradeBadgeEl.style.background = badgeBg;
    gradeBadgeEl.style.borderColor = badgeBorder;
    gradeBadgeEl.style.color = badgeColor;

    // Sub-metrics
    const comp = report.component_scores || {};
    phishingValEl.textContent = `${comp.phishing_hygiene_score ?? "--"}%`;
    certValEl.textContent = `${comp.ssl_tls_security_score ?? "--"}%`;
    vulnValEl.textContent = `${comp.header_hardening_score ?? "--"}%`;

    // Red Flags
    const flags = report.critical_red_flags || [];
    if (flags.length > 0) {
      flagsSectionEl.style.display = "block";
      flagsListEl.innerHTML = "";
      flags.slice(0, 3).forEach((flag) => {
        const item = document.createElement("div");
        item.className = "flag-item";
        item.textContent = `• ${flag}`;
        flagsListEl.appendChild(item);
      });
    } else {
      flagsSectionEl.style.display = "none";
    }
  }

  /**
   * Request scan from background service worker.
   */
  function fetchScan(force = false) {
    verdictTextEl.textContent = force ? "RESCANNING TARGET..." : "AUDITING SECURITY...";
    chrome.runtime.sendMessage(
      {
        type: "GET_TAB_SCAN",
        tabId: activeTab.id,
        url: currentUrl,
        force,
      },
      (response) => {
        if (response && response.report) {
          renderReport(response.report);
        } else {
          verdictTextEl.textContent = "SERVICE UNAVAILABLE";
        }
      }
    );
  }

  // Initial fetch
  fetchScan(false);

  // Button: Open Full Report in Dashboard
  btnDashboard.addEventListener("click", () => {
    const dashboardUrl = `http://localhost:3000/dashboard?url=${encodeURIComponent(currentUrl)}`;
    chrome.tabs.create({ url: dashboardUrl });
  });

  // Button: Rescan
  btnRescan.addEventListener("click", () => {
    fetchScan(true);
  });
});

