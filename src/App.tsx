import { ReactNode, useState } from "react";
import MessageTab from "./components/MessageTab";
import UrlTab from "./components/UrlTab";
import ScreenshotTab from "./components/ScreenshotTab";
import EmailTab from "./components/EmailTab";
import { cn } from "./utils/cn";

type TabKey = "message" | "url" | "screenshot" | "email";

const TABS: { key: TabKey; label: string; icon: ReactNode }[] = [
  {
    key: "message",
    label: "Message",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="h-4 w-4">
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
      </svg>
    ),
  },
  {
    key: "url",
    label: "URL",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="h-4 w-4">
        <path strokeLinecap="round" strokeLinejoin="round" d="M10 13a5 5 0 007.07 0l2.83-2.83a5 5 0 00-7.07-7.07l-1.5 1.5" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M14 11a5 5 0 00-7.07 0L4.1 13.83a5 5 0 007.07 7.07l1.5-1.5" />
      </svg>
    ),
  },
  {
    key: "screenshot",
    label: "Screenshot",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="h-4 w-4">
        <rect x="3" y="3" width="18" height="18" rx="2" />
        <circle cx="8.5" cy="8.5" r="1.5" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 15l-5-5L5 21" />
      </svg>
    ),
  },
  {
    key: "email",
    label: "Email",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="h-4 w-4">
        <rect x="2" y="4" width="20" height="16" rx="2" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M2 7l10 6 10-6" />
      </svg>
    ),
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<TabKey>("message");

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-indigo-50 pb-16">
      <header className="border-b border-slate-100 bg-white/80 backdrop-blur">
        <div className="mx-auto flex max-w-4xl items-center gap-3 px-4 py-5 sm:px-6">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-600 shadow-lg shadow-indigo-200">
            <svg viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth={2} className="h-6 w-6">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M9.5 12l1.8 1.8L15 10" />
            </svg>
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-slate-900">ScamShield</h1>
            <p className="text-sm text-slate-500">Check messages, links, screenshots &amp; emails for scam risk</p>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-4 pt-8 sm:px-6">
        <div className="flex flex-wrap gap-2 rounded-2xl bg-white p-2 shadow-sm ring-1 ring-slate-100">
          {TABS.map((tab) => (
            <button
              key={tab.key}
              type="button"
              onClick={() => setActiveTab(tab.key)}
              className={cn(
                "flex flex-1 items-center justify-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold transition",
                activeTab === tab.key
                  ? "bg-indigo-600 text-white shadow-sm"
                  : "text-slate-500 hover:bg-slate-50 hover:text-slate-700",
              )}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>

        <section className="mt-6 rounded-2xl bg-white p-5 shadow-sm ring-1 ring-slate-100 sm:p-6">
          {activeTab === "message" && <MessageTab />}
          {activeTab === "url" && <UrlTab />}
          {activeTab === "screenshot" && <ScreenshotTab />}
          {activeTab === "email" && <EmailTab />}
        </section>

        <p className="mt-6 text-center text-xs text-slate-400">
          ScamShield gives an automated risk assessment as guidance only — always use your own judgement and verify
          through official channels before acting.
        </p>
      </main>
    </div>
  );
}
