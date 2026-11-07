/**
 * TrustWeaver Shield - Aggressive Threat Blocker (Content Script)
 *
 * Runs at document_start. When a critical security threat is detected by the backend,
 * aggressively injects a full-screen, red blocking overlay into the DOM,
 * neutralizing interaction with the malicious page and detailing the exact reasons
 * (e.g., "Broken certificate trust chain detected", "Credential phishing detected").
 */

(function () {
  "use strict";

  const OVERLAY_ID = "trustweaver-critical-overlay";

  window.TrustWeaverBlocker = {
    render: function (report) {
      if (document.getElementById(OVERLAY_ID)) return;

      // Extract specific reasons
      const score = report.digital_trust_score ?? 0;
      const flags = report.critical_red_flags || [];
      const certData = report.raw_telemetry?.certificate_validation;
      const phishingData = report.raw_telemetry?.phishing_analysis;
      const targetUrl = report.target_url || window.location.href;

      // Highlight specific vulnerability reason (e.g. Broken certificate / eMudhra / Phishing)
      let primaryReason = "High-risk cyber threat detected on this host.";
      let reasonDetails = [];

      if (certData?.compromised_ca_alerts?.length > 0) {
        const ca = certData.compromised_ca_alerts[0];
        primaryReason = `Broken certificate trust chain detected (Flagged CA: ${ca.ca_name})`;
        reasonDetails.push(ca.description);
      } else if (certData?.weak_cryptography_flags?.length > 0) {
        primaryReason = "Broken certificate trust chain detected (Weak cryptography / Insecure TLS)";
        reasonDetails.push(...certData.weak_cryptography_flags);
      } else if (phishingData?.brand_impersonation?.detected) {
        const brand = phishingData.brand_impersonation.brands?.[0]?.brand || "Targeted Brand";
        primaryReason = `Credential harvesting brand impersonation detected (Spoofing ${brand})`;
        reasonDetails.push("This website is posing as an authentic service to harvest user passwords and sensitive tokens.");
      } else if (flags.length > 0) {
        primaryReason = flags[0];
        reasonDetails = flags.slice(1);
      }

      // Freeze scrolling on the host document
      if (document.body) {
        document.body.style.overflow = "hidden";
      }
      document.documentElement.style.overflow = "hidden";

      // Create full-screen red warning overlay
      const overlay = document.createElement("div");
      overlay.id = OVERLAY_ID;
      overlay.style.cssText = `
        position: fixed !important;
        inset: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        z-index: 2147483647 !important;
        background: radial-gradient(circle at center, #7f1d1d 0%, #450a0a 60%, #170303 100%) !important;
        color: #ffffff !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        padding: 24px !important;
        box-sizing: border-box !important;
        user-select: none !important;
        backdrop-filter: blur(16px) !important;
      `;

      const dashboardUrl = `http://localhost:3000/dashboard?url=${encodeURIComponent(targetUrl)}`;

      overlay.innerHTML = `
        <div style="max-width: 680px; width: 100%; background: rgba(15, 3, 3, 0.92); border: 2px solid #ef4444; border-radius: 20px; padding: 36px; box-shadow: 0 0 80px rgba(239, 68, 68, 0.5); text-align: center; box-sizing: border-box;">
          
          <!-- Pulsing Hazard Shield Icon -->
          <div style="width: 72px; height: 72px; margin: 0 auto 20px auto; background: rgba(239, 68, 68, 0.2); border: 2px solid #ef4444; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 36px; box-shadow: 0 0 30px rgba(239, 68, 68, 0.6);">
            🛑
          </div>

          <!-- Alert Header -->
          <div style="display: inline-block; background: rgba(239, 68, 68, 0.25); border: 1px solid #ef4444; color: #fca5a5; font-size: 11px; font-weight: 800; letter-spacing: 2px; text-transform: uppercase; padding: 4px 14px; border-radius: 20px; margin-bottom: 12px;">
            CRITICAL THREAT BLOCKED • TRUST SCORE: ${score}/100
          </div>

          <h1 style="font-size: 24px; font-weight: 900; color: #ffffff; margin: 0 0 12px 0; letter-spacing: -0.5px; line-height: 1.3;">
            Warning: Malicious Website Blocked
          </h1>

          <p style="font-size: 14px; color: #fecdd3; margin: 0 0 24px 0; line-height: 1.5; font-weight: 600;">
            ${primaryReason}
          </p>

          <!-- Diagnostic Red Flags Box -->
          <div style="background: rgba(40, 5, 5, 0.7); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 12px; padding: 16px; text-align: left; margin-bottom: 24px; max-height: 160px; overflow-y: auto;">
            <div style="font-size: 10px; font-weight: 800; color: #f87171; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 8px;">
              Detected Forensic Violations:
            </div>
            <ul style="margin: 0; padding-left: 20px; font-size: 12px; color: #fca5a5; line-height: 1.6;">
              ${
                reasonDetails.length > 0
                  ? reasonDetails.map((r) => `<li>${r}</li>`).join("")
                  : flags.slice(0, 4).map((f) => `<li>${f}</li>`).join("")
              }
            </ul>
          </div>

          <!-- Safety Call to Actions -->
          <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; margin-bottom: 20px;">
            <button id="trustweaver-btn-safety" style="background: #ef4444; color: #ffffff; border: none; padding: 12px 28px; border-radius: 10px; font-size: 14px; font-weight: 800; cursor: pointer; box-shadow: 0 4px 15px rgba(239, 68, 68, 0.4); transition: transform 0.15s ease;">
              ← Go Back to Safety
            </button>

            <a href="${dashboardUrl}" target="_blank" style="background: rgba(255, 255, 255, 0.1); color: #ffffff; border: 1px solid rgba(255, 255, 255, 0.2); padding: 12px 24px; border-radius: 10px; font-size: 14px; font-weight: 700; text-decoration: none; display: inline-flex; align-items: center; justify-content: center;">
              View Forensic Report ↗
            </a>
          </div>

          <!-- Unsafe Bypass Confirmation Toggle -->
          <div>
            <button id="trustweaver-btn-bypass" style="background: transparent; border: none; color: #94a3b8; font-size: 11px; text-decoration: underline; cursor: pointer;">
              Advanced: Ignore warning and proceed to unsafe site (Not Recommended)
            </button>
          </div>
        </div>
      `;

      document.documentElement.appendChild(overlay);

      // Event: Go back to safety
      const safetyBtn = overlay.querySelector("#trustweaver-btn-safety");
      if (safetyBtn) {
        safetyBtn.addEventListener("click", () => {
          if (window.history.length > 1) {
            window.history.back();
          } else {
            window.location.href = "about:blank";
          }
        });
      }

      // Event: Advanced bypass
      const bypassBtn = overlay.querySelector("#trustweaver-btn-bypass");
      if (bypassBtn) {
        bypassBtn.addEventListener("click", () => {
          const confirmProceed = window.confirm(
            "CRITICAL SECURITY WARNING:\n\nThis website has been flagged for severe security violations (credential phishing or broken certificate trust chain). Continuing may compromise your credentials, passwords, or personal security.\n\nDo you still wish to proceed?"
          );
          if (confirmProceed) {
            overlay.remove();
            document.documentElement.style.overflow = "";
            if (document.body) document.body.style.overflow = "";
          }
        });
      }
    },
  };

  // If fallback injector ran prior to content.js readiness
  if (window.__pendingTrustWeaverReport) {
    window.TrustWeaverBlocker.render(window.__pendingTrustWeaverReport);
    delete window.__pendingTrustWeaverReport;
  }

  // Listen for block triggers from background.js
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "TRIGGER_CRITICAL_BLOCK_OVERLAY" && message.report) {
      window.TrustWeaverBlocker.render(message.report);
    }
  });
})();
