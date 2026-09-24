import { useRef, useState } from "react";
import { createWorker } from "tesseract.js";
import { analyzeText } from "../lib/scamEngine";
import { AnalysisResult } from "../lib/types";
import ResultPanel from "./ResultPanel";

type OcrStatus = "idle" | "loading" | "error" | "done";

export default function ScreenshotTab() {
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [ocrStatus, setOcrStatus] = useState<OcrStatus>("idle");
  const [extractedText, setExtractedText] = useState<string>("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const resetAnalysisState = () => {
    setOcrStatus("idle");
    setExtractedText("");
    setErrorMessage(null);
    setResult(null);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0] ?? null;

    // Selecting an image must NEVER auto-trigger OCR/analysis.
    resetAnalysisState();

    if (previewUrl) URL.revokeObjectURL(previewUrl);

    if (!selected) {
      setFile(null);
      setPreviewUrl(null);
      return;
    }

    if (!selected.type.startsWith("image/")) {
      setFile(null);
      setPreviewUrl(null);
      setErrorMessage("Please select a valid image file (PNG, JPG, etc.).");
      return;
    }

    setFile(selected);
    setPreviewUrl(URL.createObjectURL(selected));
  };

  const handleInspect = async () => {
    if (!file || ocrStatus === "loading") return;
    setOcrStatus("loading");
    setErrorMessage(null);
    setResult(null);

    let worker: Awaited<ReturnType<typeof createWorker>> | null = null;
    try {
      worker = await createWorker("eng", 1, {
        workerPath: "https://cdn.jsdelivr.net/npm/tesseract.js@7.0.0/dist/worker.min.js",
        logger: (message) => {
          if (message.status === "recognizing text") {
            setOcrStatus("loading");
          }
        },
        errorHandler: (workerError) => {
          console.error("Tesseract worker error:", workerError);
        },
      });
      const {
        data: { text },
      } = await worker.recognize(file);

      const cleanedText = (text || "").trim();
      setExtractedText(cleanedText);

      if (!cleanedText) {
        setOcrStatus("error");
        setErrorMessage("No readable text could be found in this screenshot. Try a clearer image.");
        return;
      }

      const outcome = analyzeText(cleanedText);
      setResult(outcome);
      setOcrStatus("done");
    } catch (err) {
      console.error(err);
      setOcrStatus("error");
      setErrorMessage("Something went wrong while reading this screenshot. Please try again with a clearer image.");
    } finally {
      if (worker) {
        try {
          await worker.terminate();
        } catch {
          /* ignore termination errors */
        }
      }
    }
  };

  const handleRemove = () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setFile(null);
    setPreviewUrl(null);
    resetAnalysisState();
    if (inputRef.current) inputRef.current.value = "";
  };

  return (
    <div>
      <div
        className="flex flex-col items-center justify-center gap-3 rounded-2xl border-2 border-dashed border-slate-200 bg-slate-50 p-8 text-center transition hover:border-indigo-300"
      >
        {previewUrl ? (
          <div className="w-full max-w-sm">
            <img src={previewUrl} alt="Selected screenshot preview" className="mx-auto max-h-72 rounded-xl border border-slate-200 object-contain shadow-sm" />
            <p className="mt-2 truncate text-xs text-slate-400">{file?.name}</p>
          </div>
        ) : (
          <>
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-indigo-100 text-indigo-600">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="h-6 w-6">
                <rect x="3" y="3" width="18" height="18" rx="2" />
                <circle cx="8.5" cy="8.5" r="1.5" />
                <path d="M21 15l-5-5L5 21" />
              </svg>
            </div>
            <p className="text-sm font-medium text-slate-600">Choose a screenshot to inspect</p>
            <p className="text-xs text-slate-400">PNG or JPG. Nothing is analyzed until you click "Inspect Screenshot".</p>
          </>
        )}

        <div className="mt-2 flex items-center gap-3">
          <label className="cursor-pointer rounded-xl border border-slate-300 bg-white px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm transition hover:bg-slate-50">
            {previewUrl ? "Choose a different image" : "Choose Image"}
            <input ref={inputRef} type="file" accept="image/*" onChange={handleFileChange} className="hidden" />
          </label>
          {previewUrl && (
            <button type="button" onClick={handleRemove} className="text-sm font-medium text-slate-400 hover:text-slate-600">
              Remove
            </button>
          )}
        </div>
      </div>

      <div className="mt-4 flex items-center gap-3">
        <button
          type="button"
          onClick={handleInspect}
          disabled={!file || ocrStatus === "loading"}
          className="inline-flex items-center gap-2 rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:bg-slate-300"
        >
          {ocrStatus === "loading" && (
            <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
            </svg>
          )}
          {ocrStatus === "loading" ? "Inspecting screenshot…" : "Inspect Screenshot"}
        </button>
      </div>

      {ocrStatus === "loading" && (
        <p className="mt-3 text-sm text-slate-500">Reading text from the screenshot, this can take a few seconds…</p>
      )}

      {errorMessage && (
        <div className="mt-4 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          <p className="font-semibold">Couldn't inspect this screenshot</p>
          <p className="mt-1">{errorMessage}</p>
        </div>
      )}

      {ocrStatus === "done" && extractedText && (
        <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-400">Extracted Text (OCR)</p>
          <p className="mt-1 whitespace-pre-wrap text-sm text-slate-600">{extractedText}</p>
        </div>
      )}

      {result && <ResultPanel result={result} sourceLabel="Screenshot Analysis (OCR)" />}
    </div>
  );
}
