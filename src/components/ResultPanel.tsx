import { useState } from "react";
import RiskGauge from "./RiskGauge";
import { AnalysisResult, LEVEL_META } from "../lib/types";

interface ResultPanelProps {
  result: AnalysisResult;
  sourceLabel: string;
  extraInfo?: { label: string; value: string }[];
}

export default function ResultPanel({ result, sourceLabel, extraInfo }: ResultPanelProps) {
  const [showDetails, setShowDetails] = useState(false);
  const meta = LEVEL_META[result.level];

  const realReasons = result.isClean ? [] : result.reasons;

  return (
    <div className="mt-6 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className={`flex flex-col gap-4 border-b border-slate-100 p-5 sm:flex-row sm:items-center sm:justify-between`}>
        <div className="flex items-center gap-4">
          <RiskGauge score={result.score} level={result.level} size={104} />
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">{sourceLabel}</p>
            <h3 className="mt-1 text-lg font-semibold text-slate-900">{result.category}</h3>
            <p className="mt-1 text-sm text-slate-500">
              {result.isClean
                ? "No suspicious indicators detected."
                : `${realReasons.length} indicator${realReasons.length === 1 ? "" : "s"} found.`}
            </p>
            {extraInfo && extraInfo.length > 0 && (
              <dl className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-400">
                {extraInfo.map((item) => (
                  <div key={item.label} className="flex gap-1">
                    <dt className="font-medium text-slate-500">{item.label}:</dt>
                    <dd className="break-all">{item.value}</dd>
                  </div>
                ))}
              </dl>
            )}
          </div>
        </div>
        <button
          type="button"
          onClick={() => setShowDetails((v) => !v)}
          className={`inline-flex shrink-0 items-center justify-center gap-2 self-start rounded-xl border px-4 py-2 text-sm font-semibold transition sm:self-center ${
            showDetails
              ? "border-slate-300 bg-slate-100 text-slate-700 hover:bg-slate-200"
              : "border-indigo-200 bg-indigo-50 text-indigo-700 hover:bg-indigo-100"
          }`}
        >
          {showDetails ? "Hide Details" : "View Detailed Analysis"}
          <svg
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            className={`h-4 w-4 transition-transform ${showDetails ? "rotate-180" : ""}`}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 9l6 6 6-6" />
          </svg>
        </button>
      </div>

      {showDetails && (
        <div className="space-y-5 p-5">
          <section>
            <h4 className="text-sm font-semibold text-slate-800">Why this result?</h4>
            <ul className="mt-2 space-y-1.5">
              {(result.isClean ? ["No suspicious indicators detected."] : result.reasons).map((reason, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-slate-600">
                  <span
                    className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${result.isClean ? "bg-emerald-400" : "bg-slate-400"}`}
                  />
                  {reason}
                </li>
              ))}
            </ul>
          </section>

          <section>
            <h4 className="text-sm font-semibold text-slate-800">What should I do now?</h4>
            <ul className="mt-2 space-y-1.5">
              {result.recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-slate-600">
                  <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${meta.text.replace("text", "bg")}`} />
                  {rec}
                </li>
              ))}
            </ul>
          </section>

          {result.preventionTips.length > 0 ? (
            <section className="rounded-xl bg-slate-50 p-4">
              <h4 className="text-sm font-semibold text-slate-800">Prevention Tips</h4>
              <ul className="mt-2 space-y-1.5">
                {result.preventionTips.map((tip, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-600">
                    <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-slate-400" />
                    {tip}
                  </li>
                ))}
              </ul>
            </section>
          ) : (
            <section className="rounded-xl bg-emerald-50 p-3 text-sm text-emerald-700">
              You're good to go. No specific safety action is needed for this content.
            </section>
          )}
        </div>
      )}
    </div>
  );
}
