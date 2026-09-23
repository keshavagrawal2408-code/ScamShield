import { AnalysisResult, levelFromScore } from "./types";

export interface UrlAnalysisResult extends AnalysisResult {
  hostname: string | null;
  isValid: boolean;
}

const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "cutt.ly", "rebrand.ly", "shorte.st", "ow.ly"];

const SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".tk", ".gq", ".ml", ".cf", ".work", ".loan", ".support", ".win", ".icu"];

const BRAND_DOMAIN_MAP: Record<string, string> = {
  paypal: "paypal.com",
  amazon: "amazon.com",
  google: "google.com",
  microsoft: "microsoft.com",
  apple: "apple.com",
  facebook: "facebook.com",
  instagram: "instagram.com",
  netflix: "netflix.com",
  whatsapp: "whatsapp.com",
  sbi: "onlinesbi.sbi",
  hdfc: "hdfcbank.com",
  icici: "icicibank.com",
};

const SENSITIVE_PATH_WORDS = ["login", "verify", "secure", "update", "confirm", "account", "signin", "password", "reset"];

function dedupe(arr: string[]): string[] {
  return Array.from(new Set(arr));
}

/**
 * Standalone URL/link analysis engine used by the URL tab. Kept separate
 * from the text scam engine because URL structure heuristics (IP hosts,
 * punycode, typosquatting, shorteners...) are fundamentally different
 * signals from message-content heuristics.
 */
export function analyzeUrl(rawInput: string): UrlAnalysisResult {
  const trimmed = (rawInput || "").trim();

  if (!trimmed) {
    return {
      score: 0,
      level: "LOW",
      category: "No Suspicious Activity Detected",
      reasons: ["No suspicious indicators detected."],
      recommendations: ["No specific action is required."],
      preventionTips: [],
      isClean: true,
      hostname: null,
      isValid: false,
    };
  }

  const hadProtocol = /^https?:\/\//i.test(trimmed);
  const normalized = hadProtocol ? trimmed : `http://${trimmed}`;

  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    return {
      score: 55,
      level: "MEDIUM",
      category: "Invalid URL",
      reasons: ["The provided text is not a well-formed URL."],
      recommendations: ["Double-check the address for typos and make sure it is a complete URL before trusting it."],
      preventionTips: ["Type website addresses manually or use a saved bookmark instead of pasting unfamiliar links."],
      isClean: false,
      hostname: null,
      isValid: false,
    };
  }

  const hostname = url.hostname.toLowerCase();
  const reasons: string[] = [];
  let score = 0;

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 30;
    reasons.push("The link uses a raw IP address instead of a domain name — a common phishing trick.");
  }

  if (trimmed.includes("@")) {
    score += 25;
    reasons.push('The link contains an "@" symbol, which can be used to disguise the real destination.');
  }

  if (/xn--/i.test(hostname)) {
    score += 25;
    reasons.push("The domain uses punycode encoding, which can be used to impersonate a legitimate site (homograph attack).");
  }

  if (SHORTENERS.some((s) => hostname === s || hostname.endsWith(`.${s}`))) {
    score += 18;
    reasons.push("Uses a link-shortening service that hides the real destination.");
  }

  if (SUSPICIOUS_TLDS.some((t) => hostname.endsWith(t))) {
    score += 15;
    reasons.push("Uses a domain extension frequently associated with spam/phishing sites.");
  }

  const subdomainCount = Math.max(0, hostname.split(".").length - 2);
  if (subdomainCount >= 3) {
    score += 12;
    reasons.push("The domain has an unusually high number of subdomains, often used to disguise the real host.");
  }

  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    score += 10;
    reasons.push("The domain contains multiple hyphens, a pattern often used in fake lookalike domains.");
  }

  for (const [brand, officialDomain] of Object.entries(BRAND_DOMAIN_MAP)) {
    if (hostname.includes(brand)) {
      const matchesOfficial = hostname === officialDomain || hostname.endsWith(`.${officialDomain}`);
      if (!matchesOfficial) {
        score += 30;
        reasons.push(`The domain mimics "${brand}" but is not an official ${brand} domain — likely typosquatting.`);
      }
    }
  }

  const path = `${url.pathname}${url.search}`.toLowerCase();
  const hits = SENSITIVE_PATH_WORDS.filter((w) => path.includes(w));
  if (hits.length >= 2) {
    score += 12;
    reasons.push("The URL path combines multiple sensitive keywords (e.g. login/verify/secure), a common phishing pattern.");
  }

  if (url.protocol !== "https:") {
    score += 8;
    reasons.push("The link does not use a secure HTTPS connection.");
  }

  if (trimmed.length > 90) {
    score += 6;
    reasons.push("The URL is unusually long, which can be used to hide its real destination.");
  }

  score = Math.min(100, score);

  if (reasons.length === 0) {
    return {
      score: 0,
      level: "LOW",
      category: "No Suspicious Activity Detected",
      reasons: ["No suspicious indicators detected."],
      recommendations: ["No specific action is required."],
      preventionTips: [],
      isClean: true,
      hostname,
      isValid: true,
    };
  }

  if (score < 20) {
    return {
      score,
      level: "LOW",
      category: "Low Risk – Minor Signals Only",
      reasons,
      recommendations: ["No specific action is required, but stay cautious before entering any personal information."],
      preventionTips: [],
      isClean: false,
      hostname,
      isValid: true,
    };
  }

  const category =
    score >= 50 ? "Likely Phishing / Malicious Link" : "Suspicious Link – Exercise Caution";

  const recommendations = [
    "Do not enter your password, OTP, or card details on this page.",
  ];
  if (hits.length >= 2 || score >= 50) {
    recommendations.push("Open the official app or type the website address manually instead of clicking this link.");
  }
  recommendations.push("If you already entered any credentials on this link, change your password immediately and contact your bank/service provider.");

  const preventionTips = [
    "Hover over links to preview the real destination before clicking.",
    "Check for HTTPS and a correctly spelled domain name before entering any information.",
  ];

  return {
    score,
    level: levelFromScore(score),
    category,
    reasons: dedupe(reasons),
    recommendations: dedupe(recommendations),
    preventionTips: dedupe(preventionTips),
    isClean: false,
    hostname,
    isValid: true,
  };
}
