"useclient";

import React, { useState } from "react";

export interface CompromisedCAAlert {
  ca_name: string;
  incident: string;
  severity: string;
  description: string;
  issuer_dn?: string;
}

export interface CertValidationData {
  target?: string;
  connection_success?: boolean;
  verdict?: "TRUSTED" | "WEAK" | "DANGEROUS" | "FAILED" | string;
  cert_risk_score?: number;
  subject?: string;
  issuer?: string;
  serial_number?: string;
  validity?: {
    not_before?: string;
    not_after?: string;
    days_to_expiry?: number;
    is_expired?: boolean;
  };
  cryptographic_details?: {
    key_type?: string;
    key_size_bits?: number;
    signature_hash?: string;
    negotiated_tls_version?: string;
    negotiated_cipher?: string;
  };
  weak_cryptography_flags?: string[];
  compromised_ca_alerts?: CompromisedCAAlert[];
  subject_alternative_names?: string[];
  hostname_matched?: boolean;
  all_flags?: string[];
  error?: string;
}

interface CertDetailsProps {
  data?: CertValidationData;
}

export default function CertDetails({ data }: CertDetailsProps) {
  const [showSans, setShowSans] = useState(false);

  if (!data) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-6 text-center text-slate-400">
        No certificate data available for this target.
      </div>
    );
  }

  const isTrusted = data.verdict === "TRUSTED";
  const isWeak = data.verdict === "WEAK";
  const isDangerous = data.verdict === "DANGEROUS" || (data.compromised_ca_alerts && data.compromised_ca_alerts.length > 0);
  const isFailed = data.connection_success === false || data.verdict === "FAILED";

  const caAlerts = data.compromised_ca_alerts || [];
  const weakFlags = data.weak_cryptography_flags || [];
  const sans = data.subject_alternative_names || [];

  return (
    <div className="space-y-6">
      {/* 1. Header Banner & Trust Status */}
      <div className="flex flex-col justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900/80 p-5 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400 ring-1 ring-cyan-500/20">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                />
              </svg>
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">SSL/TLS Certificate Chain Trust</h3>
              <p className="text-xs text-slate-400">Target: {data.target || "Remote Host"}</p>
            </div>
          </div>
        </div>

        {/* Status Badge */}
        <div className="flex items-center gap-2">
          {isDangerous && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/40 bg-rose-500/15 px-3 py-1 text-xs font-bold text-rose-400">
              <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse" />
              COMPROMISED / UNTRUSTED CA
            </span>
          )}
          {isWeak && !isDangerous && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/15 px-3 py-1 text-xs font-bold text-amber-400">
              <span className="h-2 w-2 rounded-full bg-amber-500" />
              WEAK CRYPTOGRAPHY
            </span>
          )}
          {isTrusted && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-3 py-1 text-xs font-bold text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              CERTIFICATE VALID & TRUSTED
            </span>
          )}
          {isFailed && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-800 px-3 py-1 text-xs font-bold text-slate-400">
              CONNECTION FAILED
            </span>
          )}
        </div>
      </div>

      {/* 2. Compromised CA High-Priority Incident Alerts (e.g. eMudhra TLS Incident) */}
      {caAlerts.length > 0 && (
        <div className="space-y-3">
          {caAlerts.map((alert, i) => (
            <div
              key={i}
              className="rounded-xl border border-rose-500/40 bg-rose-950/30 p-4 ring-1 ring-rose-500/30"
            >
              <div className="flex items-start gap-3">
                <div className="mt-0.5 flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full bg-rose-500/20 text-rose-400">
                  <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="2"
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                    />
                  </svg>
                </div>
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-bold uppercase tracking-wider text-rose-300">
                      Security Alert: {alert.incident}
                    </h4>
                    <span className="rounded bg-rose-500/20 px-2 py-0.5 text-[10px] font-extrabold tracking-widest text-rose-300">
                      {alert.severity}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-rose-200/90 leading-relaxed">
                    {alert.description}
                  </p>
                  <p className="mt-2 font-mono text-[11px] text-rose-300/70">
                    Flagged Authority: <span className="font-semibold text-rose-200">{alert.ca_name}</span>
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* 3. Certificate Identity & Issuer Grid */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {/* Subject (Who it is issued to) */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Certificate Subject (Issued To)
          </span>
          <p className="mt-1 break-all font-mono text-xs text-slate-200">
            {data.subject || "Not available"}
          </p>
          <div className="mt-3 flex items-center gap-2">
            <span className="text-[11px] text-slate-400">Hostname match:</span>
            {data.hostname_matched ? (
              <span className="inline-flex items-center text-xs font-semibold text-emerald-400">
                ✓ Matched
              </span>
            ) : (
              <span className="inline-flex items-center text-xs font-semibold text-rose-400">
                ✗ Mismatch Detected
              </span>
            )}
          </div>
        </div>

        {/* Issuer (Certificate Authority) */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Issuer Authority (Issued By)
          </span>
          <p className="mt-1 break-all font-mono text-xs text-slate-200">
            {data.issuer || "Not available"}
          </p>
          <div className="mt-3 text-[11px] text-slate-400">
            Serial: <span className="font-mono text-slate-300">{data.serial_number || "N/A"}</span>
          </div>
        </div>
      </div>

      {/* 4. Cryptographic Hygiene & Protocol Specifications */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300">
          Cryptographic Specifications & Ciphers
        </h4>

        <div className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
          {/* Key Type & Size */}
          <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-3">
            <span className="text-[10px] uppercase text-slate-500 font-semibold">Public Key</span>
            <p className="mt-1 text-sm font-bold text-white">
              {data.cryptographic_details?.key_type || "N/A"}{" "}
              <span className="text-xs font-normal text-slate-400">
                ({data.cryptographic_details?.key_size_bits || 0}-bit)
              </span>
            </p>
          </div>

          {/* Signature Hash */}
          <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-3">
            <span className="text-[10px] uppercase text-slate-500 font-semibold">Signature Hash</span>
            <p className="mt-1 text-sm font-bold text-white">
              {data.cryptographic_details?.signature_hash || "N/A"}
            </p>
          </div>

          {/* Negotiated TLS */}
          <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-3">
            <span className="text-[10px] uppercase text-slate-500 font-semibold">TLS Protocol</span>
            <p className="mt-1 text-sm font-bold text-cyan-400">
              {data.cryptographic_details?.negotiated_tls_version || "N/A"}
            </p>
          </div>

          {/* Validity Days */}
          <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-3">
            <span className="text-[10px] uppercase text-slate-500 font-semibold">Days to Expiry</span>
            <p
              className={`mt-1 text-sm font-bold ${
                (data.validity?.days_to_expiry ?? 0) < 14
                  ? "text-rose-400"
                  : "text-emerald-400"
              }`}
            >
              {data.validity?.days_to_expiry ?? "N/A"} days
            </p>
          </div>
        </div>

        {/* Cipher suite string */}
        {data.cryptographic_details?.negotiated_cipher && (
          <div className="mt-3 flex items-center justify-between rounded-lg border border-slate-800/60 bg-slate-950/40 px-3 py-2 text-xs">
            <span className="text-slate-400">Active Cipher Suite:</span>
            <span className="font-mono text-cyan-300">
              {data.cryptographic_details.negotiated_cipher}
            </span>
          </div>
        )}
      </div>

      {/* 5. Cryptographic Weaknesses and Warnings */}
      {weakFlags.length > 0 && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-950/20 p-4">
          <h4 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-amber-400">
            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Cryptographic Weaknesses & Protocol Issues
          </h4>
          <ul className="mt-2 space-y-1.5 pl-6 list-disc text-xs text-amber-200/90">
            {weakFlags.map((flag, idx) => (
              <li key={idx}>{flag}</li>
            ))}
          </ul>
        </div>
      )}

      {/* 6. Subject Alternative Names (SANs) */}
      {sans.length > 0 && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Subject Alternative Names ({sans.length} domains)
            </span>
            <button
              onClick={() => setShowSans(!showSans)}
              className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              {showSans ? "Collapse" : "View All"}
            </button>
          </div>

          <div className="mt-3 flex flex-wrap gap-1.5">
            {(showSans ? sans : sans.slice(0, 6)).map((san, idx) => (
              <span
                key={idx}
                className="rounded-md border border-slate-800 bg-slate-950 px-2 py-0.5 font-mono text-[11px] text-slate-300"
              >
                {san}
              </span>
            ))}
            {!showSans && sans.length > 6 && (
              <span className="rounded-md border border-slate-800 bg-slate-950 px-2 py-0.5 text-[11px] text-slate-500">
                +{sans.length - 6} more
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

