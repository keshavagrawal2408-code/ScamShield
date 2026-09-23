import { useState } from "react";
import { analyzeText } from "../lib/scamEngine";
import { AnalysisResult } from "../lib/types";
import ResultPanel from "./ResultPanel";

const SAMPLES = [
  {
    label: "Sample 1 · Friendly chat",
    text: "Hey bro, let's meet tomorrow at 5 PM.",
  },
  {
    label: "Sample 2 · Hindi chat",
    text: "चलो भाई कल शाम को पाँच बजे मिलते हैं।",
  },
  {
    label: "Sample 3 · Bank phishing",
    text: "Your SBI account will be blocked today. Verify your KYC immediately by clicking this link and entering your OTP.",
  },
  {
    label: "Sample 4 · Lottery scam",
    text: "Congratulations! You have won a lucky draw prize of $5000. Pay a processing fee to claim your reward now.",
  },
];

export default function MessageTab() {
  const [message, setMessage] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleSample = (text: string) => {
    setMessage(text);
    setResult(null);
  };

  const handleAnalyze = () => {
    if (!message.trim() || isAnalyzing) return;
    setIsAnalyzing(true);
    setResult(null);
    // Simulate a brief analysis step so the loading state is visible & consistent
    // with the other tabs, without changing the underlying synchronous engine.
    window.setTimeout(() => {
      const outcome = analyzeText(message);
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
            onClick={() => handleSample(sample.text)}
            className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-600 transition hover:border-indigo-200 hover:bg-indigo-50 hover:text-indigo-700"
          >
            {sample.label}
          </button>
        ))}
      </div>

      <textarea
        value={message}
        onChange={(e) => {
          setMessage(e.target.value);
          setResult(null);
        }}
        rows={6}
        placeholder="Paste or type the message you want to check..."
        className="mt-4 w-full resize-none rounded-xl border border-slate-200 bg-white p-4 text-sm text-slate-800 shadow-sm outline-none focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
      />

      <div className="mt-4 flex items-center gap-3">
        <button
          type="button"
          onClick={handleAnalyze}
          disabled={!message.trim() || isAnalyzing}
          className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-slate-300"
        >
          {isAnalyzing && (
            <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
            </svg>
          )}
          {isAnalyzing ? "Analyzing..." : "Analyze Message"}
        </button>
        {message.trim() && !isAnalyzing && (
          <button
            type="button"
            onClick={() => {
              setMessage("");
              setResult(null);
            }}
            className="text-sm font-medium text-slate-400 hover:text-slate-600"
          >
            Clear
          </button>
        )}
      </div>

      {result && <ResultPanel result={result} sourceLabel="Message Analysis" />}
    </div>
  );
}
