"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import TrustScoreRing from "@/components/TrustScoreRing";

const SAMPLE_TARGETS = [
  { label: "Google", url: "https://google.com" },
  { label: "GitHub", url: "https://github.com" },
  { label: "Phishing Demo", url: "http://login-microsoft-verify.top/account" },
  { label: "Weak TLS Demo", url: "https://expired.badssl.com" },
];

interface ScanPreviewData {
  target_url?: string;
  report_id?: string;
  digital_trust_score?: number;
  trust_grade?: string;
  overall_verdict?: string;
  executive_summary?: string;
  component_scores?: {
    phishing_hygiene_score?: number;
    ssl_tls_security_score?: number;
    header_hardening_score?: number;
  };
}

interface RecentAuditItem {
  report_id: string;
  target_url: string;
  scanned_domain: string;
  digital_trust_score: number;
  trust_grade: string;
  overall_verdict: string;
  created_at: string;
}

const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export default function LandingPage() {
  const router = useRouter();
  const [inputUrl, setInputUrl] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanPreviewData | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [recentAudits, setRecentAudits] = useState<RecentAuditItem[]>([]);

  React.useEffect(() => {
    let isCancelled = false;
    const fetchRecentAudits = async () => {
      try {
        const response = await fetch(`${apiUrl}/scans/recent?limit=8`);
        if (response.ok) {
          const list: RecentAuditItem[] = await response.json();
          if (!isCancelled) {
            setRecentAudits(list);
          }
        }
      } catch {
        // Fallback gracefully
      }
    };
    fetchRecentAudits();
    return () => {
      isCancelled = true;
    };
  }, [scanResult]);

  const handleScan = async (targetUrlToScan?: string) => {
    const target = (targetUrlToScan || inputUrl).trim();
    if (!target) return;

    // Normalize URL
    const normalizedUrl = target.startsWith("http://") || target.startsWith("https://")
      ? target
      : `https://${target}`;

    setIsLoading(true);
    setErrorMessage(null);

    try {
      const response = await fetch(`${apiUrl}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalizedUrl }),
      });

      if (!response.ok) {
        throw new Error(`Scan server returned status ${response.status}`);
      }

      const data: ScanPreviewData = await response.json();
      setScanResult(data);
      setInputUrl(normalizedUrl);
    } catch (err: unknown) {
      console.warn("Backend scan failed or offline:", err);
      setErrorMessage(
        `Could not connect to Hackmatrix backend at ${apiUrl}. Ensure the FastAPI service is running.`
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleScan();
  };

  const handleOpenDetailedReport = () => {
    if (inputUrl) {
      router.push(`/dashboard?url=${encodeURIComponent(inputUrl)}`);
    } else {
      router.push("/dashboard");
    }
  };

  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-100 selection:bg-cyan-500 selection:text-white">
      {/* Glow gradient background elements */}
      <div className="pointer-events-none fixed inset-0 flex justify-center overflow-hidden">
        <div className="h-[400px] w-[800px] -translate-y-1/2 rounded-full bg-cyan-600/10 blur-[140px]" />
        <div className="h-[300px] w-[600px] translate-y-1/2 rounded-full bg-blue-600/10 blur-[160px]" />
      </div>

      {/* Navigation Header */}
      <header className="relative z-10 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/25">
              <svg className="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <span className="text-xl font-black tracking-tight text-white">TrustWeaver</span>
              <span className="ml-1.5 rounded bg-cyan-500/15 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-cyan-400 border border-cyan-500/30">
                Shield
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <button
              onClick={() => router.push("/dashboard")}
              className="text-sm font-semibold text-slate-300 hover:text-white transition-colors"
            >
              Dashboard
            </button>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
              AI Router Active
            </span>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="relative z-10 flex-1">
        {/* Hero Section */}
        <section className="mx-auto max-w-5xl px-6 pt-16 pb-12 text-center sm:pt-24 sm:pb-16">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-4 py-1.5 text-xs font-semibold text-cyan-300">
            <span className="flex h-2 w-2 rounded-full bg-cyan-400" />
            Dual-Tier AI Security Architecture • Gemma 2 & Llama 3.3 70B
          </div>

          <h1 className="mt-6 text-4xl font-extrabold tracking-tight text-white sm:text-6xl sm:leading-tight">
            Real-Time AI Web Trust &amp; <br />
            <span className="bg-gradient-to-r from-cyan-400 via-blue-400 to-indigo-400 bg-clip-text text-transparent">
              Threat Intelligence Shield
            </span>
          </h1>

          <p className="mx-auto mt-6 max-w-2xl text-base text-slate-400 sm:text-lg">
            Audit URLs for credential phishing kits, brand impersonation, broken cryptography,
            compromised Certificate Authorities (including the eMudhra incident), and header hardening.
          </p>

          {/* Prominent Accessible Search Bar */}
          <div className="mx-auto mt-10 max-w-3xl">
            <form onSubmit={handleSubmit} className="relative flex flex-col gap-3 sm:flex-row">
              <div className="relative flex-1">
                <label htmlFor="url-input" className="sr-only">
                  Target Website URL to Audit
                </label>
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-4 text-slate-500">
                  <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                  </svg>
                </div>
                <input
                  id="url-input"
                  type="text"
                  value={inputUrl}
                  onChange={(e) => setInputUrl(e.target.value)}
                  placeholder="Enter URL to audit (e.g., https://example.com)"
                  className="w-full rounded-xl border border-slate-700/80 bg-slate-900/90 py-4 pl-12 pr-4 text-base text-white placeholder-slate-500 shadow-2xl backdrop-blur-sm transition-all focus:border-cyan-500 focus:bg-slate-900 focus:outline-none focus:ring-2 focus:ring-cyan-500/30"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-8 py-4 text-base font-bold text-white shadow-xl shadow-cyan-500/20 transition-all hover:from-cyan-400 hover:to-blue-500 focus:outline-none focus:ring-2 focus:ring-cyan-400 focus:ring-offset-2 focus:ring-offset-slate-950 disabled:opacity-60"
              >
                {isLoading ? (
                  <>
                    <svg className="h-5 w-5 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    <span>Auditing...</span>
                  </>
                ) : (
                  <>
                    <span>Scan &amp; Audit</span>
                    <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14 5l7 7m0 0l-7 7m7-7H3" />
                    </svg>
                  </>
                )}
              </button>
            </form>

            {/* Quick Benchmark Targets */}
            <div className="mt-4 flex flex-wrap items-center justify-center gap-2 text-xs text-slate-400">
              <span className="font-semibold text-slate-500">Quick Test Targets:</span>
              {SAMPLE_TARGETS.map((sample, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => {
                    setInputUrl(sample.url);
                    handleScan(sample.url);
                  }}
                  className="rounded-lg border border-slate-800 bg-slate-900/60 px-2.5 py-1 text-slate-300 transition-colors hover:border-cyan-500/40 hover:text-cyan-300"
                >
                  {sample.label}
                </button>
              ))}
            </div>

            {/* Error Notice */}
            {errorMessage && (
              <div className="mt-4 rounded-xl border border-rose-500/40 bg-rose-950/30 p-4 text-left text-xs text-rose-300">
                <span className="font-bold">Scan Error: </span>
                {errorMessage}
              </div>
            )}
          </div>
        </section>

        {/* Live Scan Preview Section */}
        {scanResult && (
          <section className="mx-auto max-w-4xl px-6 pb-16">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/90 p-6 shadow-2xl backdrop-blur-xl sm:p-8">
              <div className="flex flex-col items-center justify-between gap-6 border-b border-slate-800 pb-6 sm:flex-row">
                <div className="text-center sm:text-left">
                  <span className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
                    Live Audit Result
                  </span>
                  <h2 className="mt-1 text-2xl font-black text-white break-all">
                    {scanResult.target_url}
                  </h2>
                  <p className="mt-1 text-xs text-slate-400">
                    Report ID: <span className="font-mono text-slate-300">{scanResult.report_id}</span>
                  </p>
                </div>

                <TrustScoreRing
                  score={scanResult.digital_trust_score ?? 0}
                  grade={scanResult.trust_grade}
                  verdict={scanResult.overall_verdict}
                  size={150}
                  strokeWidth={12}
                />
              </div>

              {/* Component Scores Bar */}
              <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
                <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-4">
                  <span className="text-xs font-medium text-slate-400">Phishing Hygiene</span>
                  <p className="mt-1 text-xl font-bold text-emerald-400">
                    {scanResult.component_scores?.phishing_hygiene_score || 0}%
                  </p>
                </div>
                <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-4">
                  <span className="text-xs font-medium text-slate-400">SSL / TLS Security</span>
                  <p className="mt-1 text-xl font-bold text-cyan-400">
                    {scanResult.component_scores?.ssl_tls_security_score || 0}%
                  </p>
                </div>
                <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-4">
                  <span className="text-xs font-medium text-slate-400">Header Hardening</span>
                  <p className="mt-1 text-xl font-bold text-blue-400">
                    {scanResult.component_scores?.header_hardening_score || 0}%
                  </p>
                </div>
              </div>

              {/* Executive Summary */}
              {scanResult.executive_summary && (
                <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950/40 p-4 text-left">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                    AI Threat Intelligence Summary
                  </h3>
                  <p className="mt-2 text-xs text-slate-300 leading-relaxed">
                    {scanResult.executive_summary}
                  </p>
                </div>
              )}

              {/* Action Button */}
              <div className="mt-6 flex justify-end">
                <button
                  onClick={handleOpenDetailedReport}
                  className="inline-flex items-center gap-2 rounded-xl bg-cyan-500/20 border border-cyan-500/40 px-5 py-2.5 text-sm font-bold text-cyan-300 hover:bg-cyan-500/30 transition-all"
                >
                  <span>Open Full Forensic Report</span>
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 8l4 4m0 0l-4 4m4-4H3" />
                  </svg>
                </button>
              </div>
            </div>
          </section>
        )}

        {/* Feature Grid */}
        <section className="mx-auto max-w-7xl px-6 py-16">
          <div className="text-center">
            <h2 className="text-xs font-bold uppercase tracking-widest text-cyan-400">
              Multi-Layer Defense
            </h2>
            <p className="mt-2 text-3xl font-black text-white">
              Comprehensive Security Orchestration
            </p>
          </div>

          <div className="mt-12 grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
            {/* Module 1 */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 transition-all hover:border-slate-700">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-400 ring-1 ring-emerald-500/20">
                <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h3 className="mt-4 text-base font-bold text-white">Phishing &amp; Forms</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                DOM credential harvesting inspection, unauthorized form action tracking, and brand impersonation targeting major brands.
              </p>
            </div>

            {/* Module 2 */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 transition-all hover:border-slate-700">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400 ring-1 ring-cyan-500/20">
                <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <h3 className="mt-4 text-base font-bold text-white">SSL/TLS Chain Audit</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Cryptographic strength validation, factorable RSA, and compromised CA detection addressing the eMudhra TLS incident.
              </p>
            </div>

            {/* Module 3 */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 transition-all hover:border-slate-700">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-500/10 text-blue-400 ring-1 ring-blue-500/20">
                <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
              </div>
              <h3 className="mt-4 text-base font-bold text-white">Headers &amp; Hardening</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Evaluates HSTS, Content-Security-Policy (CSP), and flags server version leaks aiding attacker reconnaissance.
              </p>
            </div>

            {/* Module 4 */}
            <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 transition-all hover:border-slate-700">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-purple-500/10 text-purple-400 ring-1 ring-purple-500/20">
                <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
              <h3 className="mt-4 text-base font-bold text-white">Dual-Tier AI Router</h3>
              <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                Sentence Transformers dynamically route tasks to Local Gemma 2 for heuristics or Cloud Llama 3.3 70B on Groq for deep reasoning.
              </p>
            </div>
          </div>
        </section>

        {/* Recent Audits Live Database Section */}
        {recentAudits.length > 0 && (
          <section className="mx-auto max-w-7xl px-6 pb-16">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-sm font-bold uppercase tracking-widest text-cyan-400">
                  Historical Intelligence
                </h2>
                <p className="mt-1 text-2xl font-black text-white">
                  Recently Audited Websites
                </p>
              </div>
              <span className="text-xs text-slate-500 font-mono">SQLite Persistent Store</span>
            </div>

            <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {recentAudits.map((item) => (
                <div
                  key={item.report_id}
                  onClick={() => router.push(`/dashboard?url=${encodeURIComponent(item.target_url)}`)}
                  className="group cursor-pointer rounded-xl border border-slate-800/80 bg-slate-900/60 p-4 transition-all hover:border-cyan-500/40 hover:bg-slate-900"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs text-slate-400 truncate max-w-[150px]">
                      {item.scanned_domain}
                    </span>
                    <span
                      className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase ${
                        item.trust_grade === "A"
                          ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                          : item.trust_grade === "B"
                          ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30"
                          : item.trust_grade === "C"
                          ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                          : "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                      }`}
                    >
                      Grade {item.trust_grade}
                    </span>
                  </div>

                  <div className="mt-3 flex items-baseline justify-between">
                    <span className="text-2xl font-black text-white">
                      {item.digital_trust_score}
                      <span className="text-xs text-slate-500 font-normal">/100</span>
                    </span>
                    <span className="text-[11px] font-semibold text-slate-400">
                      {item.overall_verdict.replace(/_/g, " ")}
                    </span>
                  </div>

                  <div className="mt-3 flex items-center justify-between text-[10px] text-slate-500 border-t border-slate-800/60 pt-2">
                    <span className="font-mono">{item.report_id}</span>
                    <span className="group-hover:text-cyan-400 transition-colors">View Report →</span>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-950 py-6 text-center text-xs text-slate-500">
        TrustWeaver Platform • Hackmatrix Security Shield • Dual-Tier AI
      </footer>
    </div>
  );
}
