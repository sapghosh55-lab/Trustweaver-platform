"useclient";

import React from "react";

interface TrustScoreRingProps {
  score: number;
  grade?: string;
  verdict?: string;
  size?: number;
  strokeWidth?: number;
  showDetails?: boolean;
}

export default function TrustScoreRing({
  score,
  grade,
  verdict,
  size = 180,
  strokeWidth = 14,
  showDetails = true,
}: TrustScoreRingProps) {
  // Clamp score between 0 and 100
  const normalizedScore = Math.max(0, Math.min(100, Math.round(score)));

  // SVG dimensions
  const center = size / 2;
  const radius = center - strokeWidth;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  // Determine color scheme based on score & grade
  let colorClass = "text-emerald-500 stroke-emerald-500";
  let bgGlow = "shadow-emerald-500/20";
  let gradeBadgeColor = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
  let computedGrade = grade || (normalizedScore >= 90 ? "A" : normalizedScore >= 75 ? "B" : normalizedScore >= 60 ? "C" : normalizedScore >= 40 ? "D" : "F");

  if (normalizedScore >= 90) {
    colorClass = "text-emerald-400 stroke-emerald-400";
    bgGlow = "shadow-emerald-500/25";
    gradeBadgeColor = "bg-emerald-500/15 text-emerald-400 border-emerald-500/40";
  } else if (normalizedScore >= 75) {
    colorClass = "text-cyan-400 stroke-cyan-400";
    bgGlow = "shadow-cyan-500/25";
    gradeBadgeColor = "bg-cyan-500/15 text-cyan-400 border-cyan-500/40";
  } else if (normalizedScore >= 60) {
    colorClass = "text-amber-400 stroke-amber-400";
    bgGlow = "shadow-amber-500/25";
    gradeBadgeColor = "bg-amber-500/15 text-amber-400 border-amber-500/40";
  } else if (normalizedScore >= 40) {
    colorClass = "text-orange-400 stroke-orange-400";
    bgGlow = "shadow-orange-500/25";
    gradeBadgeColor = "bg-orange-500/15 text-orange-400 border-orange-500/40";
  } else {
    colorClass = "text-rose-500 stroke-rose-500";
    bgGlow = "shadow-rose-500/30";
    gradeBadgeColor = "bg-rose-500/15 text-rose-400 border-rose-500/40";
  }

  return (
    <div className="flex flex-col items-center justify-center">
      <div
        className={`relative flex items-center justify-center rounded-full p-2 shadow-2xl transition-all duration-700 ${bgGlow}`}
        style={{ width: size, height: size }}
        role="progressbar"
        aria-valuenow={normalizedScore}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Digital Trust Score"
      >
        <svg
          width={size}
          height={size}
          className="rotate-[-90deg] transform"
          viewBox={`0 0 ${size} ${size}`}
        >
          {/* Subtle background track */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            stroke="currentColor"
            strokeWidth={strokeWidth}
            className="text-slate-800"
            fill="transparent"
          />

          {/* Foreground animated score ring */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            stroke="currentColor"
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className={`${colorClass} transition-all duration-1000 ease-out`}
            fill="transparent"
          />
        </svg>

        {/* Center score & grade display */}
        <div className="absolute flex flex-col items-center justify-center text-center">
          <div className="flex items-baseline">
            <span className="text-4xl font-black tracking-tight text-white sm:text-5xl">
              {normalizedScore}
            </span>
            <span className="ml-1 text-xs font-semibold text-slate-400">/100</span>
          </div>

          <div
            className={`mt-1 inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-bold uppercase tracking-wider ${gradeBadgeColor}`}
          >
            Grade {computedGrade}
          </div>
        </div>
      </div>

      {showDetails && verdict && (
        <div className="mt-3 flex flex-col items-center">
          <span className="text-xs uppercase tracking-widest text-slate-400">Trust Verdict</span>
          <span className="text-sm font-semibold tracking-wide text-slate-200">
            {verdict.replace(/_/g, " ")}
          </span>
        </div>
      )}
    </div>
  );
}

