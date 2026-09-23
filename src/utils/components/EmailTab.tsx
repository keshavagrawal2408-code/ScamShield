import { useState } from "react";
import { analyzeEmail } from "../lib/scamEngine";
import { AnalysisResult } from "../lib/types";
import ResultPanel from "./ResultPanel";

const SAMPLES = [
  {
    label: "Sample 1 · Normal email",
    sender: "Priya Sharma <priya.sharma@gmail.com>",
    subject: "Dinner plans this weekend",
    body: "Hey! Are we still on for dinner on Saturday? Let me know what time works for you.",
  },
  {
    label: "Sample 2 · Bank phishing",
    sender: "SBI Security Team <sbi-alerts@secure-mail-update.xyz>",
    subject: "Urgent: Your account will be suspended",
    body: "Dear Customer, your SBI account will be blocked today due to incomplete KYC. Verify your KYC immediately by clicking this link and entering your OTP to avoid suspension.",
  },
];

export default function EmailTab() {
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleSample = (sample: (typeof SAMPLES)[number]) => {
    setSender(sample.sender);
    setSubject(sample.subject);
    setBody(sample.body);
    setResult(null);
  };

  const canAnalyze = sender.trim() || subject.trim() || body.trim();

  const handleAnalyze = () => {
    if (!canAnalyze || isAnalyzing) return;
    setIsAnalyzing(true);
    setResult(null);
    window.setTimeout(() => {
      const outcome = analyzeEmail({ sender, subject, body });
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
            onClick={() => handleSample(sample)}
            className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-600 transition hover:border-indigo-200 hover:bg-indigo-50 hover:text-indigo-700"
          >
            {sample.label}
          </button>
        ))}
      </div>

      <div className="mt-4 space-y-3">
        <div>
          <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-400">
            Sender
          </label>
          <input
            type="text"
            value={sender}
            onChange={(e) => {
              setSender(e.target.value);
              setResult(null);
            }}
            placeholder="e.g. Support Team <support@example.com>"
            className="w-full rounded-xl border border-slate-200 bg-white p-3 text-sm text-slate-800 shadow-sm outline-none focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-400">
            Subject
          </label>
          <input
            type="text"
            value={subject}
            onChange={(e) => {
              setSubject(e.target.value);
              setResult(null);
            }}
            placeholder="Email subject line"
            className="w-full rounded-xl border border-slate-200 bg-white p-3 text-sm text-slate-800 shadow-sm outline-none focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-400">
            Body
          </label>
          <textarea
            value={body}
            onChange={(e) => {
              setBody(e.target.value);
              setResult(null);
            }}
            rows={6}
            placeholder="Paste the email content here..."
            className="w-full resize-none rounded-xl border border-slate-200 bg-white p-3 text-sm text-slate-800 shadow-sm outline-none focus:border-indigo-400 focus:ring-2 focus:ring-indigo-100"
          />
        </div>
      </div>

      <div className="mt-4 flex items-center gap-3">
        <button
          type="button"
          onClick={handleAnalyze}
          disabled={!canAnalyze || isAnalyzing}
          className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-slate-300"
        >
          {isAnalyzing && (
            <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
            </svg>
          )}
          {isAnalyzing ? "Analyzing..." : "Analyze Email"}
        </button>
        {canAnalyze && !isAnalyzing && (
          <button
            type="button"
            onClick={() => {
              setSender("");
              setSubject("");
              setBody("");
              setResult(null);
            }}
            className="text-sm font-medium text-slate-400 hover:text-slate-600"
          >
            Clear
          </button>
        )}
      </div>

      {result && <ResultPanel result={result} sourceLabel="Email Analysis" />}
    </div>
  );
}
