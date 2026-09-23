export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface AnalysisResult {
  score: number;
  level: RiskLevel;
  category: string;
  reasons: string[];
  recommendations: string[];
  preventionTips: string[];
  /** true when no suspicious indicator at all was found (genuinely clean content) */
  isClean: boolean;
}

export function levelFromScore(score: number): RiskLevel {
  if (score < 20) return "LOW";
  if (score < 50) return "MEDIUM";
  if (score < 75) return "HIGH";
  return "CRITICAL";
}

export const LEVEL_META: Record<
  RiskLevel,
  { label: string; color: string; ring: string; bg: string; text: string }
> = {
  LOW: {
    label: "Low Risk",
    color: "#16a34a",
    ring: "stroke-emerald-500",
    bg: "bg-emerald-50",
    text: "text-emerald-700",
  },
  MEDIUM: {
    label: "Medium Risk",
    color: "#d97706",
    ring: "stroke-amber-500",
    bg: "bg-amber-50",
    text: "text-amber-700",
  },
  HIGH: {
    label: "High Risk",
    color: "#ea580c",
    ring: "stroke-orange-500",
    bg: "bg-orange-50",
    text: "text-orange-700",
  },
  CRITICAL: {
    label: "Critical Risk",
    color: "#dc2626",
    ring: "stroke-red-600",
    bg: "bg-red-50",
    text: "text-red-700",
  },
};
