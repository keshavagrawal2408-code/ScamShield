import { AnalysisResult, levelFromScore } from "./types";

/**
 * Core scam-detection engine.
 *
 * Design principles (do not violate these when editing):
 * - Detection is based on MEANINGFUL COMBINATIONS of signals (urgency + credential
 *   request, prize claim + advance fee, etc.), not isolated everyday words.
 * - A single common word (account, link, verify, payment, call, urgent...) must
 *   NEVER by itself push a message above "clean".
 * - The same engine (`analyzeText`) is reused by messages, OCR-extracted
 *   screenshot text, and email bodies so results stay consistent across modes.
 */

interface Indicator {
  id: string;
  weight: number;
  group:
    | "threat"
    | "credential"
    | "link"
    | "incentive"
    | "investment"
    | "fee"
    | "emotional"
    | "job"
    | "impersonation"
    | "generic";
  reason: string;
  test: (text: string) => boolean;
}

const NEGATION_WORDS =
  /\b(do not|don't|dont|never|please don't|please do not|will never|should not|shouldn't|no need to)\b/i;

/** Matches a phrase-producing regex against text but ignores matches that are
 * preceded by a negation within a short window (e.g. "Do not share your OTP"
 * is protective advice, not a scam request). */
function hasPhraseWithoutNegation(text: string, regex: RegExp, window = 28): boolean {
  const matches = text.matchAll(regex);
  for (const m of matches) {
    if (m.index === undefined) continue;
    const start = Math.max(0, m.index - window);
    const context = text.slice(start, m.index);
    if (!NEGATION_WORDS.test(context)) return true;
  }
  return false;
}

const INDICATORS: Indicator[] = [
  {
    id: "account_block_threat",
    weight: 25,
    group: "threat",
    reason: "Claims your account, card, or number will be blocked, suspended, or deactivated to create panic.",
    test: (t) =>
      /\b(account|profile|card|number|sim|policy|wallet)\b[^.!?]{0,25}\b(block(ed)?|suspend(ed)?|deactivat(e|ed|ion)|froz(e|en)|lock(ed)?|expir(e|ed|ing))\b/i.test(
        t,
      ),
  },
  {
    id: "urgency_language",
    weight: 12,
    group: "threat",
    reason: 'Uses urgent, high-pressure language ("immediately", "act now", "within 24 hours"...).',
    test: (t) =>
      /\b(act\s*now|immediately|urgent(ly)?|right\s*away|without\s+delay|within\s+\d+\s*(hours?|minutes?|hrs?|days?)|expires?\s+(today|soon)|last\s+warning|final\s+notice|failure\s+to\s+comply)\b/i.test(
        t,
      ),
  },
  {
    id: "verify_kyc",
    weight: 20,
    group: "credential",
    reason: 'Asks you to "verify" your KYC, account, or identity — a common phishing tactic.',
    test: (t) => /\bverif(y|ication)\s+(your\s+)?(kyc|account|identity|details|information)\b/i.test(t),
  },
  {
    id: "credential_request",
    weight: 28,
    group: "credential",
    reason: "Directly asks you to share your OTP, password, PIN, or CVV with someone.",
    test: (t) =>
      hasPhraseWithoutNegation(
        t,
        /\b(share|send|enter|provide|tell|give|reply\s+with)\s+(your\s+)?(otp|one[- ]time\s+password|password|pin|cvv|atm\s*pin|card\s*number)\b/gi,
      ),
  },
  {
    id: "click_link_instruction",
    weight: 12,
    group: "link",
    reason: "Urges you to click a link to take urgent action.",
    test: (t) => /\b(click|tap|open)\s+(on\s+)?(this|the|here|below)?\s*(link|url)?\b/i.test(t) && /\blink\b/i.test(t),
  },
  {
    id: "contains_url",
    weight: 8,
    group: "link",
    reason: "Contains a clickable link.",
    test: (t) => /(https?:\/\/|www\.)[^\s]+/i.test(t),
  },
  {
    id: "shortened_url",
    weight: 15,
    group: "link",
    reason: "Uses a shortened/obscured link that hides the real destination.",
    test: (t) => /\b(bit\.ly|tinyurl\.com|t\.co|is\.gd|goo\.gl|shorte\.st|cutt\.ly|rebrand\.ly|ow\.ly)\b/i.test(t),
  },
  {
    id: "lottery_prize",
    weight: 25,
    group: "incentive",
    reason: "Claims you have won a lottery, prize, or lucky draw you never entered.",
    test: (t) =>
      /\b(congratulations|you\s*(have|'ve)?\s*(have\s+)?won|you\s+are\s+the\s+winner|lucky\s+draw|lottery|jackpot|selected\s+for\s+a\s+prize)\b/i.test(
        t,
      ),
  },
  {
    id: "free_reward",
    weight: 12,
    group: "incentive",
    reason: "Offers a free gift, cashback, or reward to lure a response.",
    test: (t) => /\b(free\s+gift|claim\s+your\s+(prize|reward|cashback)|guaranteed\s+cashback)\b/i.test(t),
  },
  {
    id: "guaranteed_returns",
    weight: 25,
    group: "investment",
    reason: "Promises guaranteed or unrealistically high investment returns.",
    test: (t) =>
      /\b(double\s+your\s+(money|investment)|guaranteed\s+(returns?|profit)|risk[- ]free\s+investment|100\s?%\s*profit)\b/i.test(
        t,
      ),
  },
  {
    id: "advance_fee",
    weight: 22,
    group: "fee",
    reason: 'Requests an upfront "processing fee" or payment to release money, a parcel, or a prize.',
    test: (t) =>
      /\b(processing\s+fee|advance\s+fee|courier\s+fee|customs\s+fee|clearance\s+fee|release\s+fee)\b/i.test(t) ||
      /\bpay\b[^.!?]{0,20}\bto\s+(claim|release|unlock|receive)\b/i.test(t),
  },
  {
    id: "emergency_money_request",
    weight: 20,
    group: "emotional",
    reason: "Uses a fabricated emergency to pressure you into sending money.",
    test: (t) => /\b(stranded|hospital(ized)?|emergency|accident)\b[^.!?]{0,40}\b(send|transfer|wire)\s+(me\s+)?money\b/i.test(t),
  },
  {
    id: "romance_gift",
    weight: 18,
    group: "emotional",
    reason: "Combines romantic language with a request for money or gift cards.",
    test: (t) => /\b(my\s+love|my\s+dear|sweetheart|darling)\b[^.!?]{0,60}\b(money|gift\s*card|western\s+union|moneygram)\b/i.test(t),
  },
  {
    id: "job_offer_fee",
    weight: 15,
    group: "job",
    reason: "Offers easy income (work-from-home/part-time) paired with a request for fees or bank details.",
    test: (t) =>
      /\b(work\s+from\s+home|part[- ]time\s+job|daily\s+income|easy\s+money)\b/i.test(t) &&
      /\b(fee|deposit|registration|pay|bank\s+details)\b/i.test(t),
  },
  {
    id: "brand_impersonation",
    weight: 8,
    group: "impersonation",
    reason: "Mentions a bank, government body, or well-known brand name.",
    test: (t) =>
      /\b(sbi|hdfc|icici|axis\s*bank|kotak|paytm|rbi|income\s*tax\s*department|customs\s*department|paypal|amazon|microsoft|apple\s*support|netflix|whatsapp)\b/i.test(
        t,
      ),
  },
  {
    id: "generic_greeting",
    weight: 6,
    group: "generic",
    reason: 'Uses an impersonal greeting ("Dear Customer") instead of your name.',
    test: (t) => /\bdear\s+(customer|user|valued\s+customer|sir\/madam|account\s+holder)\b/i.test(t),
  },
];

interface Combo {
  id: string;
  weight: number;
  reason: string;
  condition: (ids: Set<string>) => boolean;
}

const COMBOS: Combo[] = [
  {
    id: "urgency_plus_credential",
    weight: 15,
    reason: "Combines urgency/threats with a request for sensitive credentials — a classic phishing pattern.",
    condition: (ids) =>
      (ids.has("urgency_language") || ids.has("account_block_threat")) &&
      (ids.has("credential_request") || ids.has("verify_kyc")),
  },
  {
    id: "impersonation_plus_link_plus_pressure",
    weight: 12,
    reason: "Impersonates a trusted brand/bank while urging urgent action through a link.",
    condition: (ids) =>
      ids.has("brand_impersonation") &&
      (ids.has("click_link_instruction") || ids.has("contains_url") || ids.has("shortened_url")) &&
      (ids.has("urgency_language") || ids.has("account_block_threat") || ids.has("credential_request") || ids.has("verify_kyc")),
  },
  {
    id: "prize_plus_fee",
    weight: 15,
    reason: "Classic prize-scam pattern: claims a win, then asks for an upfront fee to release it.",
    condition: (ids) => ids.has("lottery_prize") && ids.has("advance_fee"),
  },
];

function pickCategory(ids: Set<string>, score: number): string {
  if (ids.has("lottery_prize") || (ids.has("advance_fee") && ids.has("free_reward"))) return "Lottery / Prize Scam";
  if (ids.has("guaranteed_returns")) return "Investment Scam";
  if (ids.has("advance_fee")) return "Advance-Fee Fraud";
  if (ids.has("job_offer_fee")) return "Job Scam";
  if (ids.has("emergency_money_request") || ids.has("romance_gift")) return "Emotional Manipulation / Emergency Scam";
  if ((ids.has("credential_request") || ids.has("verify_kyc")) && ids.has("brand_impersonation"))
    return "Banking / KYC Phishing";
  if (ids.has("credential_request") || ids.has("verify_kyc")) return "Phishing / Credential Theft";
  if (ids.has("shortened_url") || ids.has("click_link_instruction") || ids.has("contains_url"))
    return "Suspicious Link";
  if (score > 0) return "Suspicious Content – Exercise Caution";
  return "No Suspicious Activity Detected";
}

function buildRecommendations(ids: Set<string>): string[] {
  const recs: string[] = [];
  if (ids.has("credential_request") || ids.has("verify_kyc")) {
    recs.push("Do not share your OTP, password, PIN, or CVV with anyone, even if they claim to be from your bank.");
  }
  if (ids.has("account_block_threat") || ids.has("brand_impersonation")) {
    recs.push("Contact the organization directly using the number/app on their official website — not any number or link in this message.");
  }
  if (ids.has("click_link_instruction") || ids.has("contains_url") || ids.has("shortened_url")) {
    recs.push("Avoid clicking the link. Open the official app or type the website address manually instead.");
  }
  if (ids.has("lottery_prize") || ids.has("free_reward")) {
    recs.push("Do not pay any fee to claim a prize you never entered for — legitimate prizes never require upfront payment.");
  }
  if (ids.has("advance_fee")) {
    recs.push("Never send money to release a payment, parcel, or prize. This is a common advance-fee fraud pattern.");
  }
  if (ids.has("guaranteed_returns")) {
    recs.push("Be skeptical of any investment promising guaranteed or unusually high returns — verify with a registered financial advisor.");
  }
  if (ids.has("job_offer_fee")) {
    recs.push("Verify the company independently before paying any registration fee or sharing your bank details.");
  }
  if (ids.has("emergency_money_request") || ids.has("romance_gift")) {
    recs.push("Verify the person's identity through another channel (a phone call, video call) before sending any money.");
  }
  if (recs.length === 0) {
    recs.push("No specific action is required.");
  } else {
    recs.push("If you already shared sensitive details, change your passwords and contact your bank/service provider immediately.");
  }
  return dedupe(recs);
}

function buildPreventionTips(ids: Set<string>): string[] {
  const tips: string[] = [];
  if (ids.has("credential_request") || ids.has("verify_kyc")) {
    tips.push("Never share passwords, OTPs, or banking credentials with anyone — banks and government agencies never ask for these.");
  }
  if (ids.has("account_block_threat") || ids.has("urgency_language") || ids.has("brand_impersonation")) {
    tips.push("Always verify urgent requests through official channels (official app, website, or customer care number) before acting.");
  }
  if (ids.has("lottery_prize") || ids.has("guaranteed_returns") || ids.has("free_reward")) {
    tips.push("Be skeptical of unsolicited prizes, lotteries, or investment offers that promise guaranteed rewards.");
  }
  if (ids.has("click_link_instruction") || ids.has("contains_url") || ids.has("shortened_url")) {
    tips.push("Hover/preview links before clicking, and avoid entering personal details on pages reached via unsolicited messages.");
  }
  return dedupe(tips);
}

function dedupe(arr: string[]): string[] {
  return Array.from(new Set(arr));
}

/**
 * Core text analysis used by Message tab, Screenshot OCR text, and (as a base
 * layer) Email analysis. Purely signal/combination based — no isolated
 * everyday-word matching.
 */
export function analyzeText(rawText: string): AnalysisResult {
  const text = (rawText || "").trim();

  if (!text) {
    return {
      score: 0,
      level: "LOW",
      category: "No Suspicious Activity Detected",
      reasons: ["No suspicious indicators detected."],
      recommendations: ["No specific action is required."],
      preventionTips: [],
      isClean: true,
    };
  }

  const matchedIds = new Set<string>();
  const reasons: string[] = [];
  let score = 0;

  for (const indicator of INDICATORS) {
    if (indicator.test(text)) {
      matchedIds.add(indicator.id);
      reasons.push(indicator.reason);
      score += indicator.weight;
    }
  }

  for (const combo of COMBOS) {
    if (combo.condition(matchedIds)) {
      reasons.push(combo.reason);
      score += combo.weight;
    }
  }

  score = Math.min(100, score);

  // Nothing at all detected -> genuinely clean content.
  if (matchedIds.size === 0) {
    return {
      score: 0,
      level: "LOW",
      category: "No Suspicious Activity Detected",
      reasons: ["No suspicious indicators detected."],
      recommendations: ["No specific action is required."],
      preventionTips: [],
      isClean: true,
    };
  }

  // Only very weak/minor signals matched (e.g. a single brand mention) -
  // treat as low risk without alarming recommendations.
  if (score < 20) {
    return {
      score,
      level: "LOW",
      category: "Low Risk – Minor Signals Only",
      reasons,
      recommendations: ["No specific action is required, but stay alert if anyone later asks for money or sensitive information."],
      preventionTips: [],
      isClean: false,
    };
  }

  const category = pickCategory(matchedIds, score);
  const recommendations = buildRecommendations(matchedIds);
  const preventionTips = buildPreventionTips(matchedIds);

  return {
    score,
    level: levelFromScore(score),
    category,
    reasons: dedupe(reasons),
    recommendations,
    preventionTips,
    isClean: false,
  };
}

const FREE_MAIL_DOMAINS = [
  "gmail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "rediffmail.com",
  "aol.com",
  "protonmail.com",
];

const BRAND_DOMAIN_MAP: Record<string, string> = {
  sbi: "onlinesbi.sbi",
  hdfc: "hdfcbank.com",
  icici: "icicibank.com",
  paytm: "paytm.com",
  paypal: "paypal.com",
  amazon: "amazon.com",
  microsoft: "microsoft.com",
  apple: "apple.com",
  netflix: "netflix.com",
  whatsapp: "whatsapp.com",
};

function extractEmailAddress(sender: string): string | null {
  const match = sender.match(/[\w.+-]+@[\w-]+\.[\w.-]+/i);
  return match ? match[0].toLowerCase() : null;
}

/**
 * Email analysis reuses the core text engine on subject+body, then layers
 * email-specific sender/domain checks on top, merging into one consistent
 * result so the same underlying text produces the same core risk assessment
 * across modes.
 */
export function analyzeEmail(params: { sender: string; subject: string; body: string }): AnalysisResult {
  const { sender, subject, body } = params;
  const base = analyzeText(`${subject}\n${body}`);

  const emailAddress = extractEmailAddress(sender);
  const combinedForBrandCheck = `${sender} ${subject}`.toLowerCase();

  let extraScore = 0;
  const extraReasons: string[] = [];

  if (emailAddress) {
    const domain = emailAddress.split("@")[1] || "";
    for (const [brand, officialDomain] of Object.entries(BRAND_DOMAIN_MAP)) {
      if (combinedForBrandCheck.includes(brand)) {
        const matchesOfficial = domain === officialDomain || domain.endsWith(`.${officialDomain}`);
        if (!matchesOfficial) {
          extraScore += 25;
          extraReasons.push(
            `The sender claims to be from "${brand}" but the email domain ("${domain}") does not match their official domain.`,
          );
          break;
        }
      }
    }

    if (FREE_MAIL_DOMAINS.includes(domain) && /\b(bank|kyc|account|support|security|team)\b/i.test(sender)) {
      extraScore += 15;
      extraReasons.push("Sender uses a free/personal email domain while claiming to represent an official organization.");
    }

    if (/\.(xyz|top|click|tk|gq|ml|cf|work|loan|support|win|icu)$/i.test(domain)) {
      extraScore += 12;
      extraReasons.push("Sender's email domain uses an extension frequently associated with spam/phishing.");
    }
  }

  if (extraScore === 0 && extraReasons.length === 0 && base.isClean) {
    return base;
  }

  const matchedIds = new Set<string>();
  // Re-derive matched indicator ids by re-running detection so recommendations/category stay consistent.
  const text = `${subject}\n${body}`;
  for (const indicator of INDICATORS) {
    if (indicator.test(text)) matchedIds.add(indicator.id);
  }
  if (extraReasons.length > 0) matchedIds.add("sender_domain_mismatch");

  const totalScore = Math.min(100, base.score + extraScore);
  const reasons = dedupe([...extraReasons, ...base.reasons.filter((r) => r !== "No suspicious indicators detected.")]);

  if (totalScore === 0 || reasons.length === 0) {
    return {
      score: 0,
      level: "LOW",
      category: "No Suspicious Activity Detected",
      reasons: ["No suspicious indicators detected."],
      recommendations: ["No specific action is required."],
      preventionTips: [],
      isClean: true,
    };
  }

  if (totalScore < 20) {
    return {
      score: totalScore,
      level: "LOW",
      category: "Low Risk – Minor Signals Only",
      reasons,
      recommendations: ["No specific action is required, but stay alert if anyone later asks for money or sensitive information."],
      preventionTips: [],
      isClean: false,
    };
  }

  const category = extraReasons.length > 0 && base.score < 20 ? "Sender/Domain Spoofing" : pickCategory(matchedIds, totalScore);
  const recommendations = buildRecommendations(matchedIds);
  if (extraReasons.length > 0) {
    recommendations.unshift("Do not trust the sender's display name alone — check the full email address carefully.");
  }
  const preventionTips = buildPreventionTips(matchedIds);

  return {
    score: totalScore,
    level: levelFromScore(totalScore),
    category,
    reasons,
    recommendations: dedupe(recommendations),
    preventionTips,
    isClean: false,
  };
}
