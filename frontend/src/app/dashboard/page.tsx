"use client";

import React, { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import CertDetails, { CertValidationData } from "@/components/CertDetails";
import TrustScoreRing from "@/components/TrustScoreRing";
import VerifiableLedger from "@/components/VerifiableLedger";

interface MitreTacticItem {
  tactic?: string;
  technique_id?: string;
  name?: string;
}

interface BrandTargetItem {
  brand?: string;
  is_authorized_domain?: boolean;
  current_domain?: string;
  matched_keywords?: string[];
}

interface FormItem {
  index?: number;
  action?: string;
  method?: string;
  has_password?: boolean;
  has_user_or_email?: boolean;
  is_external_action?: boolean;
  inputs_count?: number;
  inputs?: Array<{ name?: string; type?: string }>;
}

interface MissingHeaderItem {
  header?: string;
  alias?: string;
  severity?: string;
  description?: string;
  recommended?: string;
}

interface ExposedTechItem {
  source?: string;
  raw_value?: string;
  exact_version_disclosed?: boolean;
  disclosed_versions?: string[];
  risk?: string;
}

interface ForensicReport {
  report_id?: string;
  target_url?: string;
  digital_trust_score?: number;
  trust_grade?: string;
  overall_verdict?: string;
  blockchain_tx_hash?: string | null;
  on_chain_record?: {
    published?: boolean;
    status?: string;
    tx_hash?: string;
    contract_address?: string;
    explorer_url?: string;
    ipfs_hash?: string;
    threat_score?: number;
    oracle_address?: string;
    network?: string;
    note?: string;
  } | null;
  ipfs_hash?: string;
  component_scores?: {
    phishing_hygiene_score?: number;
    ssl_tls_security_score?: number;
    header_hardening_score?: number;
  };
  executive_summary?: string;
  critical_red_flags?: string[];
  mitre_attack_tactics?: MitreTacticItem[];
  recommendations?: string[];
  routing_intelligence?: {
    tier_selected?: string;
    complexity_score?: number;
    matched_prototype?: string;
    ai_success?: boolean;
  };
  raw_telemetry?: {
    phishing_analysis?: {
      url?: string;
      scanned_domain?: string;
      page_title?: string;
      verdict?: string;
      phishing_risk_score?: number;
      credential_harvesting?: {
        detected?: boolean;
        has_external_submission?: boolean;
        has_exfil_webhook?: boolean;
        forms_count?: number;
        forms?: FormItem[];
      };
      brand_impersonation?: {
        detected?: boolean;
        brands?: BrandTargetItem[];
      };
      red_flags?: string[];
    };
    certificate_validation?: CertValidationData;
    vulnerability_scan?: {
      target?: string;
      scanned_domain?: string;
      http_status_code?: number;
      success?: boolean;
      verdict?: string;
      vulnerability_risk_score?: number;
      missing_headers?: MissingHeaderItem[];
      present_headers?: Array<{
        header?: string;
        alias?: string;
        value?: string;
        is_weak?: boolean;
      }>;
      exposed_technologies?: ExposedTechItem[];
      has_version_disclosure?: boolean;
    };
  };
}

// Fallback mock report for demonstration if backend is not yet started
const MOCK_DEMO_REPORT: ForensicReport = {
  report_id: "DTS-demo7f2b",
  target_url: "https://login-microsoft-auth.secure-portal.xyz/login",
  digital_trust_score: 24,
  trust_grade: "F",
  overall_verdict: "MALICIOUS",
  blockchain_tx_hash: "0x3f9e8a71b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1",
  on_chain_record: {
    published: true,
    status: "broadcast_confirmed",
    tx_hash: "0x3f9e8a71b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1",
    contract_address: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
    explorer_url: "https://amoy.polygonscan.com/tx/0x3f9e8a71b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1",
    ipfs_hash: "QmZtmD2qt8fJpq3CLDHtaGqj9xDeTaGz9RESoWSD5WXyeN",
    threat_score: 95,
    oracle_address: "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199",
    network: "Polygon Amoy Testnet",
  },
  ipfs_hash: "QmZtmD2qt8fJpq3CLDHtaGqj9xDeTaGz9RESoWSD5WXyeN",
  component_scores: {
    phishing_hygiene_score: 5,
    ssl_tls_security_score: 30,
    header_hardening_score: 45,
  },
  executive_summary:
    "CRITICAL THREAT DETECTED: This domain exhibits high-confidence indicators of an active credential phishing operation masquerading as Microsoft Office 365. The page contains credential harvesting password forms submitting to an unverified third-party endpoint, combined with invalid certificate authority trust warnings.",
  critical_red_flags: [
    "Unauthorized Brand Impersonation: Page mimics Microsoft but is hosted on 'secure-portal.xyz'",
    "Password input field detected in DOM with external form submission action",
    "FLAGGED CA ALERT [CRITICAL]: Certificate issued by an unverified or heavily scrutinized authority",
    "Missing Critical Security Header: Strict-Transport-Security (HSTS)",
    "Missing Critical Security Header: Content-Security-Policy (CSP)",
    "Exposed Server/Software Version: Apache/2.4.52",
  ],
  mitre_attack_tactics: [
    { tactic: "Initial Access", technique_id: "T1566.002", name: "Spearphishing Link" },
    { tactic: "Credential Access", technique_id: "T1056.003", name: "Web Form Credential Harvesting" },
    { tactic: "Defense Evasion", technique_id: "T1588.004", name: "Digital Certificates Spoofing" },
  ],
  recommendations: [
    "Block access to this domain across enterprise firewalls and secure web gateways.",
    "Submit domain to Google Safe Browsing and Microsoft SmartScreen for global blocking.",
    "Reset credentials for any users who may have navigated to this URL.",
    "Deploy HTTP Strict Transport Security (HSTS) with 'max-age=31536000; includeSubDomains'.",
  ],
  routing_intelligence: {
    tier_selected: "cloud_llama",
    complexity_score: 0.842,
    matched_prototype: "Synthesize comprehensive cyber threat intelligence report from multi-source telemetry and IOCs",
    ai_success: true,
  },
  raw_telemetry: {
    phishing_analysis: {
      url: "https://login-microsoft-auth.secure-portal.xyz/login",
      scanned_domain: "login-microsoft-auth.secure-portal.xyz",
      page_title: "Sign in to your Microsoft Account",
      verdict: "PHISHING",
      phishing_risk_score: 0.95,
      credential_harvesting: {
        detected: true,
        has_external_submission: true,
        has_exfil_webhook: false,
        forms_count: 1,
        forms: [
          {
            index: 1,
            action: "https://exfil-receiver.xyz/api/collect",
            method: "POST",
            has_password: true,
            has_user_or_email: true,
            is_external_action: true,
            inputs_count: 3,
            inputs: [
              { name: "loginfmt", type: "email" },
              { name: "passwd", type: "password" },
              { name: "csrf_token", type: "hidden" },
            ],
          },
        ],
      },
      brand_impersonation: {
        detected: true,
        brands: [
          {
            brand: "Microsoft",
            is_authorized_domain: false,
            current_domain: "login-microsoft-auth.secure-portal.xyz",
            matched_keywords: ["microsoft", "sign in to your account", "office 365"],
          },
        ],
      },
      red_flags: [
        "Unauthorized Brand Impersonation: Page mimics Microsoft",
        "Form submits credentials to foreign domain: exfil-receiver.xyz",
      ],
    },
    certificate_validation: {
      target: "login-microsoft-auth.secure-portal.xyz:443",
      connection_success: true,
      verdict: "DANGEROUS",
      cert_risk_score: 0.70,
      subject: "CN=login-microsoft-auth.secure-portal.xyz",
      issuer: "CN=eMudhra Subordinate CA, O=eMudhra Consumer Services, C=IN",
      serial_number: "4820948102948192839",
      validity: {
        not_before: "2026-01-01T00:00:00Z",
        not_after: "2026-12-31T23:59:59Z",
        days_to_expiry: 53,
        is_expired: false,
      },
      cryptographic_details: {
        key_type: "RSA",
        key_size_bits: 2048,
        signature_hash: "SHA256",
        negotiated_tls_version: "TLSv1.2",
        negotiated_cipher: "ECDHE-RSA-AES256-GCM-SHA384",
      },
      weak_cryptography_flags: [],
      compromised_ca_alerts: [
        {
          ca_name: "eMudhra",
          incident: "eMudhra TLS Compliance & Distrust Incident",
          severity: "CRITICAL",
          description:
            "eMudhra root and intermediate CAs faced browser root store distrust and restriction actions following recurring compliance failures and unauthorized subordinate certificate issuance.",
          issuer_dn: "CN=eMudhra Subordinate CA, O=eMudhra Consumer Services, C=IN",
        },
      ],
      subject_alternative_names: [
        "login-microsoft-auth.secure-portal.xyz",
        "auth.secure-portal.xyz",
      ],
      hostname_matched: true,
      all_flags: [
        "FLAGGED CA ALERT [CRITICAL]: Certificate issued by eMudhra associated with TLS Compliance incident",
      ],
    },
    vulnerability_scan: {
      target: "https://login-microsoft-auth.secure-portal.xyz/login",
      scanned_domain: "login-microsoft-auth.secure-portal.xyz",
      http_status_code: 200,
      success: true,
      verdict: "POOR",
      vulnerability_risk_score: 0.55,
      missing_headers: [
        {
          header: "Strict-Transport-Security",
          alias: "HSTS",
          severity: "HIGH",
          description: "Enforces secure HTTPS transport; prevents SSL-stripping.",
          recommended: "max-age=31536000; includeSubDomains; preload",
        },
        {
          header: "Content-Security-Policy",
          alias: "CSP",
          severity: "HIGH",
          description: "Restricts sources of executable scripts, objects, and styles.",
          recommended: "default-src 'self'; script-src 'self';",
        },
        {
          header: "X-Frame-Options",
          alias: "XFO",
          severity: "MEDIUM",
          description: "Prevents clickjacking attacks by forbidding iframe rendering.",
          recommended: "DENY",
        },
      ],
      present_headers: [
        {
          header: "X-Content-Type-Options",
          alias: "XCTO",
          value: "nosniff",
          is_weak: false,
        },
      ],
      exposed_technologies: [
        {
          source: "Header: server",
          raw_value: "Apache/2.4.52 (Ubuntu)",
          exact_version_disclosed: true,
          disclosed_versions: ["Apache/2.4.52"],
          risk: "Allows attackers to cross-reference known CVE databases against your exact software version",
        },
      ],
      has_version_disclosure: true,
    },
  },
};

type TabType = "overview" | "phishing" | "cert" | "vuln" | "ai" | "ledger" | "raw";

function DashboardContent() {
  const searchParams = useSearchParams();
  const urlParam = searchParams.get("url");

  const [activeTab, setActiveTab] = useState<TabType>("overview");
  const [targetUrl, setTargetUrl] = useState(urlParam || "https://login-microsoft-auth.secure-portal.xyz/login");
  const [report, setReport] = useState<ForensicReport>(MOCK_DEMO_REPORT);
  const [isLoading, setIsLoading] = useState(false);
  const [isDemoData, setIsDemoData] = useState(true);
  const [errorNotice, setErrorNotice] = useState<string | null>(null);

  const fetchScanReport = async (urlToScan: string) => {
    setIsLoading(true);
    setErrorNotice(null);
    try {
      const response = await fetch("http://localhost:8000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: urlToScan }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: Scan service failed`);
      }

      const data: ForensicReport = await response.json();
      setReport(data);
      setIsDemoData(false);
    } catch (err: unknown) {
      console.warn("Backend unavailable, falling back to mock demonstration data:", err);
      setErrorNotice(
        "Backend scan server at http://localhost:8000 could not be reached. Displaying illustrative demo threat telemetry."
      );
      setReport(MOCK_DEMO_REPORT);
      setIsDemoData(true);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (!urlParam) return;
    let isCancelled = false;

    // Asynchronously fetch without synchronous setState in effect body
    const executeInitialScan = async () => {
      try {
        const response = await fetch("http://localhost:8000/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: urlParam }),
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: Scan service failed`);
        }

        const data: ForensicReport = await response.json();
        if (!isCancelled) {
          setReport(data);
          setIsDemoData(false);
        }
      } catch (err: unknown) {
        console.warn("Backend unavailable, falling back to mock demonstration data:", err);
        if (!isCancelled) {
          setErrorNotice(
            "Backend scan server at http://localhost:8000 could not be reached. Displaying illustrative demo threat telemetry."
          );
          setReport(MOCK_DEMO_REPORT);
          setIsDemoData(true);
        }
      }
    };

    executeInitialScan();

    return () => {
      isCancelled = true;
    };
  }, [urlParam]);

  const handleRescan = (e: React.FormEvent) => {
    e.preventDefault();
    if (targetUrl) {
      fetchScanReport(targetUrl);
    }
  };

  const phishing = report?.raw_telemetry?.phishing_analysis;
  const cert = report?.raw_telemetry?.certificate_validation;
  const vuln = report?.raw_telemetry?.vulnerability_scan;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Top Navbar */}
      <header className="sticky top-0 z-30 border-b border-slate-800 bg-slate-950/90 backdrop-blur-md">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="flex items-center gap-2 text-sm font-semibold text-slate-400 hover:text-white transition-colors"
            >
              <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
              </svg>
              <span>Back to Home</span>
            </Link>
            <span className="text-slate-700">|</span>
            <span className="text-base font-bold text-white">Forensic Trust Report</span>
          </div>

          {/* Quick Rescan Input Form */}
          <form onSubmit={handleRescan} className="flex items-center gap-2">
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="Target URL..."
              className="hidden w-64 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none sm:block"
            />
            <button
              type="submit"
              disabled={isLoading}
              className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-500/20 border border-cyan-500/40 px-3 py-1.5 text-xs font-bold text-cyan-300 hover:bg-cyan-500/30 transition-all disabled:opacity-50"
            >
              {isLoading ? (
                <span>Auditing...</span>
              ) : (
                <>
                  <svg className="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  <span>Rescan</span>
                </>
              )}
            </button>
          </form>
        </div>
      </header>

      {/* Main Dashboard Container */}
      <main className="mx-auto max-w-7xl px-6 py-8">
        {/* Notice Banner */}
        {errorNotice && (
          <div className="mb-6 rounded-xl border border-amber-500/40 bg-amber-950/20 p-4 text-xs text-amber-200">
            <span className="font-bold">Notice: </span>
            {errorNotice}
          </div>
        )}

        {isDemoData && !errorNotice && (
          <div className="mb-6 flex items-center justify-between rounded-xl border border-cyan-500/30 bg-cyan-950/20 px-4 py-3 text-xs text-cyan-300">
            <span>Displaying sample forensic telemetry report. Enter a live target above to perform live audit.</span>
            <span className="font-semibold uppercase tracking-wider text-[10px] bg-cyan-500/20 px-2 py-0.5 rounded">Demo Mode</span>
          </div>
        )}

        {/* Hero Score & Executive Summary Card */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 shadow-2xl backdrop-blur-xl sm:p-8">
          <div className="flex flex-col gap-8 lg:flex-row lg:items-center lg:justify-between">
            {/* Target & Metadata */}
            <div className="space-y-3 lg:max-w-xl">
              <div className="flex items-center gap-2">
                <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-slate-300">
                  {report?.report_id || "DTS-REPORT"}
                </span>
                <span className="text-xs text-slate-500">•</span>
                <span className="text-xs text-slate-400">Target Host Audit</span>
              </div>

              <h1 className="text-2xl font-black text-white break-all sm:text-3xl">
                {report?.target_url}
              </h1>

              <p className="text-xs text-slate-300 leading-relaxed">
                {report?.executive_summary}
              </p>
            </div>

            {/* Score Ring & Sub-meters */}
            <div className="flex flex-col items-center gap-6 sm:flex-row sm:items-center">
              <TrustScoreRing
                score={report?.digital_trust_score ?? 0}
                grade={report?.trust_grade}
                verdict={report?.overall_verdict}
                size={170}
                strokeWidth={14}
              />

              <div className="flex flex-col gap-3 min-w-[200px]">
                {/* Phishing meter */}
                <div>
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-400">Phishing Hygiene</span>
                    <span className="font-bold text-emerald-400">
                      {report?.component_scores?.phishing_hygiene_score ?? 0}%
                    </span>
                  </div>
                  <div className="mt-1 h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-emerald-500 transition-all duration-700"
                      style={{ width: `${report?.component_scores?.phishing_hygiene_score ?? 0}%` }}
                    />
                  </div>
                </div>

                {/* SSL/TLS meter */}
                <div>
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-400">SSL/TLS Security</span>
                    <span className="font-bold text-cyan-400">
                      {report?.component_scores?.ssl_tls_security_score ?? 0}%
                    </span>
                  </div>
                  <div className="mt-1 h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-cyan-500 transition-all duration-700"
                      style={{ width: `${report?.component_scores?.ssl_tls_security_score ?? 0}%` }}
                    />
                  </div>
                </div>

                {/* Header meter */}
                <div>
                  <div className="flex justify-between text-xs">
                    <span className="text-slate-400">Header Hardening</span>
                    <span className="font-bold text-blue-400">
                      {report?.component_scores?.header_hardening_score ?? 0}%
                    </span>
                  </div>
                  <div className="mt-1 h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-blue-500 transition-all duration-700"
                      style={{ width: `${report?.component_scores?.header_hardening_score ?? 0}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Critical Red Flags Alert Panel */}
        {report?.critical_red_flags && report.critical_red_flags.length > 0 && (
          <div className="mt-8 rounded-2xl border border-rose-500/40 bg-rose-950/20 p-6">
            <h2 className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-rose-400">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              Critical Security Red Flags Detected ({report.critical_red_flags.length})
            </h2>

            <div className="mt-4 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              {report.critical_red_flags.map((flag: string, idx: number) => (
                <div
                  key={idx}
                  className="flex items-start gap-2.5 rounded-lg border border-rose-500/20 bg-rose-950/40 p-3 text-xs text-rose-200/90"
                >
                  <span className="font-bold text-rose-400">!</span>
                  <span>{flag}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Transparent Threat Intelligence Ledger Verification Banner */}
        {report?.blockchain_tx_hash && (
          <div className="mt-8 rounded-2xl border border-cyan-500/40 bg-gradient-to-r from-slate-900 via-cyan-950/25 to-slate-900 p-6 shadow-2xl backdrop-blur-xl">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className="flex h-2.5 w-2.5 rounded-full bg-cyan-400 animate-pulse" />
                  <span className="text-[11px] font-bold uppercase tracking-wider text-cyan-300">
                    Transparent Threat Intelligence Ledger • On-Chain Attestation
                  </span>
                  <span className="rounded bg-cyan-500/20 border border-cyan-500/30 px-2 py-0.5 font-mono text-[10px] text-cyan-300">
                    Verified Block
                  </span>
                </div>
                <h3 className="text-lg font-black text-white sm:text-xl">
                  Immutable Blockchain Threat Proof
                </h3>
                <p className="text-xs text-slate-300 max-w-2xl leading-relaxed">
                  This domain was confirmed as a high-confidence threat and recorded on-chain in the{" "}
                  <span className="font-mono text-cyan-400">ThreatRegistry.sol</span> contract. Users and security gateways can independently verify this cryptographic proof.
                </p>
              </div>

              {/* Verification Links */}
              <div className="flex flex-wrap items-center gap-2.5 shrink-0">
                <a
                  href={
                    report.on_chain_record?.explorer_url ||
                    `https://amoy.polygonscan.com/tx/${report.blockchain_tx_hash}`
                  }
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 px-4 py-2.5 text-xs font-bold text-white shadow-lg shadow-cyan-950/50 hover:from-cyan-500 hover:to-blue-500 transition-all"
                  title="Inspect transaction on Polygonscan"
                >
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                  <span>Verify on Polygonscan</span>
                </a>

                <a
                  href={`https://sepolia.etherscan.io/tx/${report.blockchain_tx_hash}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-800/80 px-3.5 py-2.5 text-xs font-semibold text-slate-200 hover:bg-slate-700 hover:text-white transition-all"
                  title="Inspect transaction on Sepolia Etherscan"
                >
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                  </svg>
                  <span>Etherscan</span>
                </a>

                {report.ipfs_hash && (
                  <a
                    href={`https://ipfs.io/ipfs/${report.ipfs_hash}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 rounded-xl border border-cyan-500/30 bg-cyan-950/40 px-3.5 py-2.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-950/60 transition-all"
                    title={`View AI forensic report on IPFS: ${report.ipfs_hash}`}
                  >
                    <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                    </svg>
                    <span>IPFS Telemetry</span>
                  </a>
                )}
              </div>
            </div>

            {/* TxHash details row */}
            <div className="mt-4 flex flex-wrap items-center gap-x-6 gap-y-2 rounded-xl border border-slate-800 bg-slate-950/70 p-3 font-mono text-xs text-slate-400">
              <div className="flex items-center gap-2 truncate">
                <span className="text-slate-500">TxHash:</span>
                <a
                  href={
                    report.on_chain_record?.explorer_url ||
                    `https://amoy.polygonscan.com/tx/${report.blockchain_tx_hash}`
                  }
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyan-400 hover:text-cyan-300 hover:underline truncate"
                >
                  {report.blockchain_tx_hash}
                </a>
              </div>
              {report.on_chain_record?.contract_address && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">Contract:</span>
                  <a
                    href={`https://amoy.polygonscan.com/address/${report.on_chain_record.contract_address}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-slate-300 hover:text-white hover:underline"
                  >
                    {report.on_chain_record.contract_address.slice(0, 8)}...{report.on_chain_record.contract_address.slice(-6)}
                  </a>
                </div>
              )}
              {report.ipfs_hash && (
                <div className="flex items-center gap-2">
                  <span className="text-slate-500">IPFS CID:</span>
                  <a
                    href={`https://ipfs.io/ipfs/${report.ipfs_hash}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-emerald-400 hover:underline"
                  >
                    {report.ipfs_hash.slice(0, 10)}...{report.ipfs_hash.slice(-6)}
                  </a>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="mt-8 flex flex-wrap gap-2 border-b border-slate-800 pb-2">
          {(
            [
              { id: "overview", label: "Overview & MITRE" },
              { id: "ledger", label: "Transparent Threat Ledger" },
              { id: "phishing", label: "Phishing & Brand Impersonation" },
              { id: "cert", label: "SSL/TLS & CA Chain" },
              { id: "vuln", label: "Headers & Vulnerabilities" },
              { id: "ai", label: "AI Routing & Intelligence" },
              { id: "raw", label: "Raw JSON Telemetry" },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`rounded-lg px-4 py-2 text-xs font-bold transition-all ${
                activeTab === tab.id
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40"
                  : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
              }`}
            >
              {tab.label}
              {tab.id === "ledger" && report?.blockchain_tx_hash && (
                <span className="ml-1.5 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40 px-1.5 py-0.2 text-[9px]">
                  On-Chain
                </span>
              )}
            </button>
          ))}
        </div>

        {/* TAB 1: OVERVIEW & MITRE ATT&CK */}
        {activeTab === "overview" && (
          <div className="mt-6 space-y-6">
            {/* MITRE ATT&CK Matrix */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300">
                MITRE ATT&amp;CK® Techniques Observed
              </h3>
              <p className="mt-1 text-xs text-slate-400">
                Adversary tactics and procedures mapped from target page heuristics and telemetry.
              </p>

              <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
                {report?.mitre_attack_tactics?.map((mitre: MitreTacticItem, idx: number) => (
                  <div
                    key={idx}
                    className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5 space-y-1"
                  >
                    <span className="rounded bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[10px] font-bold text-cyan-400 border border-cyan-500/20">
                      {mitre.technique_id}
                    </span>
                    <h4 className="text-xs font-bold text-white pt-1">{mitre.name}</h4>
                    <p className="text-[11px] text-slate-400">Tactic: {mitre.tactic}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommendations List */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300">
                Actionable Remediation &amp; Defense Guidelines
              </h3>
              <ul className="mt-4 space-y-2.5">
                {report?.recommendations?.map((rec: string, idx: number) => (
                  <li
                    key={idx}
                    className="flex items-start gap-3 rounded-lg border border-slate-800/80 bg-slate-950/40 p-3 text-xs text-slate-300"
                  >
                    <span className="flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-cyan-500/10 text-cyan-400 text-[10px] font-bold">
                      {idx + 1}
                    </span>
                    <span className="leading-relaxed">{rec}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Transparent Threat Intelligence Ledger Feed */}
            <div className="pt-2">
              <VerifiableLedger
                currentTxHash={report?.blockchain_tx_hash}
                currentUrl={report?.target_url}
                contractAddress={report?.on_chain_record?.contract_address}
              />
            </div>
          </div>
        )}

        {/* TAB: TRANSPARENT THREAT LEDGER */}
        {activeTab === "ledger" && (
          <div className="mt-6">
            <VerifiableLedger
              currentTxHash={report?.blockchain_tx_hash}
              currentUrl={report?.target_url}
              contractAddress={report?.on_chain_record?.contract_address}
            />
          </div>
        )}

        {/* TAB 2: PHISHING & BRAND IMPERSONATION */}
        {activeTab === "phishing" && (
          <div className="mt-6 space-y-6">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white">Phishing &amp; Form Harvesting Analysis</h3>
                  <p className="text-xs text-slate-400">
                    Scanned Host: {phishing?.scanned_domain || "N/A"}
                  </p>
                </div>
                <span
                  className={`rounded-full border px-3 py-1 text-xs font-bold ${
                    phishing?.verdict === "PHISHING"
                      ? "border-rose-500/40 bg-rose-500/20 text-rose-400"
                      : "border-emerald-500/40 bg-emerald-500/20 text-emerald-400"
                  }`}
                >
                  {phishing?.verdict || "CLEAN"}
                </span>
              </div>

              {/* Brand Impersonation Detail */}
              <div className="mt-6 rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                  Brand Impersonation Status
                </span>
                {phishing?.brand_impersonation?.detected && phishing.brand_impersonation.brands ? (
                  <div className="mt-3 space-y-2">
                    {phishing.brand_impersonation.brands.map((b: BrandTargetItem, i: number) => (
                      <div
                        key={i}
                        className="rounded-lg border border-rose-500/30 bg-rose-950/30 p-3 text-xs text-rose-200"
                      >
                        <p className="font-bold text-rose-300">
                          Target Brand: {b.brand} (Impersonation Detected)
                        </p>
                        <p className="mt-1 text-[11px] text-rose-200/80">
                          Matched Keywords: {b.matched_keywords?.join(", ")}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="mt-2 text-xs text-emerald-400">
                    ✓ No brand impersonation or trademark spoofing detected.
                  </p>
                )}
              </div>

              {/* Form harvesting details */}
              <div className="mt-6">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                  Credential Harvesting Forms ({phishing?.credential_harvesting?.forms_count ?? 0})
                </h4>

                {phishing?.credential_harvesting?.forms && phishing.credential_harvesting.forms.length > 0 ? (
                  <div className="mt-3 space-y-3">
                    {phishing.credential_harvesting.forms.map((form: FormItem, idx: number) => (
                      <div
                        key={idx}
                        className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-cyan-400">Form #{form.index}</span>
                          <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300 uppercase">
                            Method: {form.method}
                          </span>
                        </div>
                        <p className="mt-2 text-slate-300 break-all font-mono text-[11px]">
                          Action: {form.action || "(Empty or current URL)"}
                        </p>
                        <div className="mt-3 flex flex-wrap gap-2">
                          {form.has_password && (
                            <span className="rounded bg-rose-500/20 border border-rose-500/30 px-2 py-0.5 text-[10px] font-bold text-rose-300">
                              Contains Password Field
                            </span>
                          )}
                          {form.is_external_action && (
                            <span className="rounded bg-rose-500/20 border border-rose-500/30 px-2 py-0.5 text-[10px] font-bold text-rose-300">
                              External Submission Target
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="mt-2 text-xs text-slate-400">
                    No forms or password inputs found in DOM.
                  </p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: SSL/TLS & CA BREAKDOWN */}
        {activeTab === "cert" && (
          <div className="mt-6">
            <CertDetails data={cert} />
          </div>
        )}

        {/* TAB 4: HEADERS & VULNERABILITIES */}
        {activeTab === "vuln" && (
          <div className="mt-6 space-y-6">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
              <h3 className="text-base font-bold text-white">Security Headers &amp; Surface Hardening</h3>
              <p className="mt-1 text-xs text-slate-400">
                Evaluation of defense-in-depth HTTP headers and server version leakage.
              </p>

              {/* Missing Headers List */}
              <div className="mt-6">
                <h4 className="text-xs font-bold uppercase tracking-wider text-rose-400">
                  Missing or Incomplete Headers ({vuln?.missing_headers?.length ?? 0})
                </h4>
                <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
                  {vuln?.missing_headers?.map((h: MissingHeaderItem, idx: number) => (
                    <div
                      key={idx}
                      className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5 space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-xs text-white">{h.header}</span>
                        <span
                          className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                            h.severity === "HIGH"
                              ? "bg-rose-500/20 text-rose-300"
                              : "bg-amber-500/20 text-amber-300"
                          }`}
                        >
                          {h.severity}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400">{h.description}</p>
                      <p className="font-mono text-[10px] text-cyan-300/80 pt-1">
                        Rec: {h.recommended}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Exposed Technologies */}
              {vuln?.exposed_technologies && vuln.exposed_technologies.length > 0 && (
                <div className="mt-6">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400">
                    Exposed Service &amp; Technology Disclosures
                  </h4>
                  <div className="mt-3 space-y-2">
                    {vuln.exposed_technologies.map((tech: ExposedTechItem, idx: number) => (
                      <div
                        key={idx}
                        className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs"
                      >
                        <div className="flex justify-between">
                          <span className="font-semibold text-slate-300">{tech.source}</span>
                          <span className="font-mono text-amber-300">{tech.raw_value}</span>
                        </div>
                        <p className="mt-1 text-[11px] text-slate-400">{tech.risk}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 5: AI ROUTING & INTELLIGENCE */}
        {activeTab === "ai" && (
          <div className="mt-6 space-y-6">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6">
              <h3 className="text-base font-bold text-white">Dual-Tier AI Routing Metadata</h3>
              <p className="mt-1 text-xs text-slate-400">
                Sentence Transformers semantic routing decisions and latency metrics.
              </p>

              <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                  <span className="text-[10px] font-bold uppercase text-slate-500">Selected Tier</span>
                  <p className="mt-1 text-base font-bold text-cyan-400 font-mono">
                    {report?.routing_intelligence?.tier_selected?.toUpperCase() || "CLOUD_LLAMA"}
                  </p>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                  <span className="text-[10px] font-bold uppercase text-slate-500">Complexity Score</span>
                  <p className="mt-1 text-base font-bold text-purple-400 font-mono">
                    {report?.routing_intelligence?.complexity_score ?? 0.85}
                  </p>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                  <span className="text-[10px] font-bold uppercase text-slate-500">Model Engine</span>
                  <p className="mt-1 text-base font-bold text-white font-mono">
                    Llama 3.3 70B (Groq)
                  </p>
                </div>
              </div>

              {report?.routing_intelligence?.matched_prototype && (
                <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/40 p-3 text-xs">
                  <span className="text-slate-400">Matched Complexity Prototype:</span>
                  <p className="mt-1 font-mono text-cyan-300">
                    &ldquo;{report.routing_intelligence.matched_prototype}&rdquo;
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* TAB 6: RAW JSON TELEMETRY */}
        {activeTab === "raw" && (
          <div className="mt-6">
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4 font-mono text-xs overflow-x-auto">
              <pre className="text-slate-300">
                {JSON.stringify(report, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-slate-950 text-cyan-400">
          <div className="flex items-center gap-2">
            <svg className="h-6 w-6 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            <span className="font-mono text-sm">Loading Forensic Intelligence Dashboard...</span>
          </div>
        </div>
      }
    >
      <DashboardContent />
    </Suspense>
  );
}
