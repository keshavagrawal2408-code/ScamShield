import { useState } from "react";
import { analyzeUrl, UrlAnalysisResult } from "../lib/urlHeuristics";
import ResultPanel from "./ResultPanel";

const SAMPLES = [
  { label: "Sample 1 · Safe site", url: "https://www.wikipedia.org" },
  { label: "Sample 2 · IP link", url: "http://192.168.10.55/login/verify-account" },
  { label: "Sample 3 · Shortened link", url: "http://bit.ly/free-prize-claim" },
  { label: "Sample 4 · Lookalike domain", url: "http://paypal-secure-login-update.xyz/confirm" },
];

export default function UrlTab() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<UrlAnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleSample = (value: string) => {
    setUrl(value);
    setResult(null);
  };

  const handleInspect = () => {
    if (!url.trim() || isAnalyzing) return;
    setIsAnalyzing(true);
    setResult(null);
    window.setTimeout(() => {
      const outcome = analyzeUrl(url);
      setResult(outcome);
      setIsAnalyzing(false);
    }, 450);
  };

  return (
    <div>
      <div className="flex flex-wrap gap-2">
        {SAMPLES.map((sample) => (
          <button
            key={sample.label}
            type="button"
            onClick={() => handleSample(sample.url)}
            className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-600 transition hover:border-indigo-200 hover:bg-indigo-50 hover:text-indigo-700"
          >
            {sample.label}
          </button>
        ))}
      </div>

      <input
        type="text"
        value={url}
        onChange={(e) => {
          setUrl(e.target.value);
          setResult(null);
        }}
        placeholder="Paste a URL to inspect, e.g. https://example.com/login"
        className="mt-4 w-full rounded-xl border border-slate-200 bg-white p-4 text-sm text-slate-800 shadow-sm outline-none focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
      />

      <div className="mt-4 flex items-center gap-3">
        <button
          type="button"
          onClick={handleInspect}
          disabled={!url.trim() || isAnalyzing}
          className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-slate-300"
        >
          {isAnalyzing && (
            <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
            </svg>
          )}
          {isAnalyzing ? "Inspecting..." : "Inspect URL"}
        </button>
        {url.trim() && !isAnalyzing && (
          <button
            type="button"
            onClick={() => {
              setUrl("");
              setResult(null);
            }}
            className="text-sm font-medium text-slate-400 hover:text-slate-600"
          >
            Clear
          </button>
        )}
      </div>

      {result && (
        <ResultPanel
          result={result}
          sourceLabel="URL Analysis"
          extraInfo={result.hostname ? [{ label: "Host", value: result.hostname }] : undefined}
        />
      )}
    </div>
  );
}
