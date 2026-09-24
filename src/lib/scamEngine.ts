import { AnalysisResult, levelFromScore } from "./types";

/**
 * Core scam-detection engine.
 *
 * Detection is based on meaningful combinations of signals rather than isolated
 * everyday words. OCR text is normalized before matching so spaces/line breaks
 * introduced by screenshots do not hide scam indicators.
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

function normalizeDetectionText(rawText: string): string {
  return (rawText || "")
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2013\u2014]/g, "-")
    .replace(/[\u00A0]/g, " ")
    .replace(/([A-Za-z])\s*[-–—]\s*([A-Za-z])/g, "$1-$2")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim();
}

function hasPhraseWithoutNegation(text: string, regex: RegExp, window = 28): boolean {
  const matches = text.matchAll(regex);
  for (const m of matches) {
    if (m.index === undefined) continue;
    const context = text.slice(Math.max(0, m.index - window), m.index);
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
    test: (t) => /\b(account|profile|card|number|sim|policy|wallet)\b[^.!?]{0,25}\b(block(ed)?|suspend(ed)?|deactivat(e|ed|ion)|froz(e|en)|lock(ed)?|expir(e|ed|ing))\b/i.test(t),
  },
  {
    id: "urgency_language",
    weight: 12,
    group: "threat",
    reason: 'Uses urgent, high-pressure language ("immediately", "act now", "within 24 hours"...).',
    test: (t) => /\b(act\s*now|click\s+now|claim\s+now|immediately|urgent(ly)?|right\s*away|without\s+delay|within\s+\d+\s*(hours?|minutes?|hrs?|days?)|expires?\s+(today|soon)|last\s+warning|final\s+notice|failure\s+to\s+comply)\b/i.test(t),
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
    reason: "Directly asks you to share your OTP, password, PIN, CVV, or card details.",
    test: (t) => hasPhraseWithoutNegation(t, /\b(share|send|enter|provide|tell|give|reply\s+with)\s+(your\s+)?(otp|one[- ]time\s+password|password|pin|cvv|atm\s*pin|card\s*(number|details?)|bank\s*details?)\b/gi),
  },
  {
    id: "payment_details_request",
    weight: 22,
    group: "credential",
    reason: "Requests bank, card, payment, or financial details in an unsolicited context.",
    test: (t) => hasPhraseWithoutNegation(t, /\b(have|keep|provide|enter|submit|share|give|send)\b[^.!?]{0,45}\b(bank\s*details?|account\s*(number|details?)|debit\s*card|credit\s*card|card\s*details?|payment\s*details?|upi\s*(id|pin)?|cvv)\b/gi),
  },
  {
    id: "click_link_instruction",
    weight: 12,
    group: "link",
    reason: "Urges you to click or open a link to take action.",
    test: (t) => /\b(click|tap|open)\s+(on\s+)?(this|the|here|below)?\s*(link|url)?\b/i.test(t) && /\blink\b/i.test(t),
  },
  {
    id: "contains_url",
    weight: 8,
    group: "link",
    reason: "Contains a clickable link or web address.",
    test: (t) => /(https?:\/\/|www\.)[^\s]+/i.test(t) || /\b[a-z0-9-]+\.(com|in|net|org|co|info|biz|xyz|top|site|online)\b/i.test(t),
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
    reason: "Claims you have won a lottery, prize, giveaway, or lucky draw you did not enter.",
    test: (t) => /\b(congratulations|you\s*(have|'ve)?\s*(have\s+)?won|you\s+are\s+the\s+winner|winner|lucky\s+draw|lottery|jackpot|giveaway|selected\s+for\s+a\s+prize)\b/i.test(t),
  },
  {
    id: "unrealistic_money_claim",
    weight: 28,
    group: "incentive",
    reason: "Claims that a person, company, or organization has unexpectedly allocated or gifted a large amount of money to ordinary users or residents.",
    test: (t) =>
      /\b(allocated|allotted|given|gifted|distributed|donated|granted|offered|set\s+aside)\b[^.!?]{0,80}\b(\$|usd|rs\.?|₹|inr)?\s*\d[\d,.]*\s*(million|lakh|crore|thousand|hundred|k|m)?\b/i.test(t) &&
      /\b(residents?|users?|people|citizens?|public|customers?|followers?|participants?|individuals?)\b/i.test(t),
  },
  {
    id: "celebrity_founder_giveaway_claim",
    weight: 24,
    group: "impersonation",
    reason: "Uses a public figure, founder, or celebrity's name to make an unsolicited money/reward claim.",
    test: (t) =>
      /\b(jeff\s+bezos|elon\s+musk|bill\s+gates|mark\s+zuckerberg|warren\s+buffett|ratan\s+tata)\b/i.test(t) &&
      /\b(allocated|given|gifted|donated|distributing|giving|reward|bonus|money|million|lakh|crore|cash|prize|fund)\b/i.test(t),
  },
  {
    id: "bonus_reward",
    weight: 16,
    group: "incentive",
    reason: "Uses an unsolicited bonus, reward, cash, or giveaway as an incentive to act.",
    test: (t) => /\b(instant\s+bonus|bonus\s+cash|cash\s+bonus|special\s+reward|exclusive\s+reward|free\s+money|money\s+reward|cash\s+prize|claim\s+your\s+bonus|claim\s+your\s+reward|unlock\s+(your\s+)?bonus|unlock\s+(your\s+)?reward)\b/i.test(t),
  },
  {
    id: "free_reward",
    weight: 12,
    group: "incentive",
    reason: "Offers a free gift, cashback, or reward to lure a response.",
    test: (t) => /\b(free\s+gift|claim\s+your\s+(prize|reward|cashback)|guaranteed\s+cashback)\b/i.test(t),
  },
  {
    id: "advance_fee",
    weight: 22,
    group: "fee",
    reason: 'Requests an upfront "processing fee" or payment to release money, a parcel, or a prize.',
    test: (t) => /\b(processing\s+fee|advance\s+fee|courier\s+fee|customs\s+fee|clearance\s+fee|release\s+fee)\b/i.test(t) || /\bpay\b[^.!?]{0,20}\bto\s+(claim|release|unlock|receive)\b/i.test(t),
  },
  {
    id: "guaranteed_returns",
    weight: 25,
    group: "investment",
    reason: "Promises guaranteed or unrealistically high investment returns.",
    test: (t) => /\b(double\s+your\s+(money|investment)|guaranteed\s+(returns?|profit)|risk[- ]free\s+investment|100\s?%\s*profit)\b/i.test(t),
  },
  {
    id: "emergency_money_request",
    weight: 20,
    group: "emotional",
    reason: "Uses a fabricated emergency to pressure you into sending money.",
    test: (t) => /\b(stranded|hospital(ized)?|emergency|accident)\b[^.!?]{0,40}\b(send|transfer|wire)\s+(me\s+)?money\b/i.test(t),
  },
  {
    id: "job_offer_fee",
    weight: 15,
    group: "job",
    reason: "Offers easy income paired with a request for fees or bank details.",
    test: (t) => /\b(work\s+from\s+home|part[- ]time\s+job|daily\s+income|easy\s+money)\b/i.test(t) && /\b(fee|deposit|registration|pay|bank\s+details)\b/i.test(t),
  },
  {
    id: "brand_impersonation",
    weight: 8,
    group: "impersonation",
    reason: "Mentions a bank, government body, public figure, or well-known brand in a potentially impersonated context.",
    test: (t) => /\b(sbi|hdfc|icici|axis\s*bank|kotak|paytm|rbi|income\s*tax\s*department|customs\s*department|paypal|amazon|microsoft|apple\s*support|netflix|whatsapp)\b/i.test(t),
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
    condition: (ids) => (ids.has("urgency_language") || ids.has("account_block_threat")) && (ids.has("credential_request") || ids.has("verify_kyc") || ids.has("payment_details_request")),
  },
  {
    id: "impersonation_plus_link_plus_pressure",
    weight: 12,
    reason: "Impersonates a trusted brand while urging action through a link or sensitive request.",
    condition: (ids) => ids.has("brand_impersonation") && (ids.has("click_link_instruction") || ids.has("contains_url") || ids.has("shortened_url")) && (ids.has("urgency_language") || ids.has("account_block_threat") || ids.has("credential_request") || ids.has("verify_kyc") || ids.has("payment_details_request")),
  },
  {
    id: "prize_plus_fee",
    weight: 15,
    reason: "Classic prize-scam pattern: claims a win or reward, then asks for an upfront fee to release it.",
    condition: (ids) => (ids.has("lottery_prize") || ids.has("bonus_reward") || ids.has("unrealistic_money_claim")) && ids.has("advance_fee"),
  },
  {
    id: "money_claim_plus_cta",
    weight: 18,
    reason: "Combines an unsolicited money/reward claim with a call to action, which is a strong giveaway-scam pattern.",
    condition: (ids) => (ids.has("unrealistic_money_claim") || ids.has("celebrity_founder_giveaway_claim") || ids.has("bonus_reward")) && (ids.has("urgency_language") || ids.has("click_link_instruction") || ids.has("contains_url") || ids.has("payment_details_request")),
  },
  {
    id: "money_claim_plus_brand",
    weight: 15,
    reason: "Combines a large unsolicited money claim with a public figure or recognizable brand identity.",
    condition: (ids) => (ids.has("unrealistic_money_claim") || ids.has("celebrity_founder_giveaway_claim")) && ids.has("brand_impersonation"),
  },
];

function pickCategory(ids: Set<string>, score: number): string {
  if (ids.has("lottery_prize") || ids.has("bonus_reward") || ids.has("unrealistic_money_claim") || ids.has("celebrity_founder_giveaway_claim")) return "Prize / Giveaway Scam";
  if (ids.has("guaranteed_returns")) return "Investment Scam";
  if (ids.has("advance_fee")) return "Advance-Fee Fraud";
  if (ids.has("job_offer_fee")) return "Job Scam";
  if (ids.has("emergency_money_request")) return "Emergency / Money Scam";
  if ((ids.has("credential_request") || ids.has("verify_kyc") || ids.has("payment_details_request")) && ids.has("brand_impersonation")) return "Banking / KYC Phishing";
  if (ids.has("credential_request") || ids.has("verify_kyc") || ids.has("payment_details_request")) return "Phishing / Credential Theft";
  if (ids.has("shortened_url") || ids.has("click_link_instruction") || ids.has("contains_url")) return "Suspicious Link";
  if (score > 0) return "Suspicious Content – Exercise Caution";
  return "No Suspicious Activity Detected";
}

function dedupe(arr: string[]): string[] {
  return Array.from(new Set(arr));
}

function buildRecommendations(ids: Set<string>): string[] {
  const recs: string[] = [];
  if (ids.has("credential_request") || ids.has("verify_kyc") || ids.has("payment_details_request")) recs.push("Do not share your OTP, password, PIN, CVV, card, UPI, or banking details.");
  if (ids.has("account_block_threat") || ids.has("brand_impersonation")) recs.push("Verify the organization independently using its official app or website, not a link or number in the message.");
  if (ids.has("click_link_instruction") || ids.has("contains_url") || ids.has("shortened_url")) recs.push("Avoid clicking unfamiliar links. Open the official website or app manually.");
  if (ids.has("lottery_prize") || ids.has("free_reward") || ids.has("bonus_reward") || ids.has("unrealistic_money_claim") || ids.has("celebrity_founder_giveaway_claim")) recs.push("Treat unsolicited prizes, giveaways, and unexpected money claims as suspicious until independently verified.");
  if (ids.has("advance_fee")) recs.push("Never send money to release a payment, parcel, bonus, or prize.");
  if (ids.has("guaranteed_returns")) recs.push("Be skeptical of guaranteed or unusually high investment returns and verify independently.");
  if (ids.has("job_offer_fee")) recs.push("Verify the company independently before paying any registration fee or sharing bank details.");
  if (recs.length === 0) recs.push("No specific action is required.");
  else recs.push("If you already shared sensitive details, change your passwords and contact the relevant bank/service provider.");
  return dedupe(recs);
}

function buildPreventionTips(ids: Set<string>): string[] {
  const tips: string[] = [];
  if (ids.has("credential_request") || ids.has("verify_kyc") || ids.has("payment_details_request")) tips.push("Never share passwords, OTPs, PINs, CVVs, or banking credentials through unsolicited messages.");
  if (ids.has("account_block_threat") || ids.has("urgency_language") || ids.has("brand_impersonation")) tips.push("Verify urgent requests through official channels before acting.");
  if (ids.has("lottery_prize") || ids.has("guaranteed_returns") || ids.has("free_reward") || ids.has("bonus_reward") || ids.has("unrealistic_money_claim")) tips.push("Be skeptical of unsolicited prizes, giveaways, or money claims that require you to act quickly.");
  if (ids.has("click_link_instruction") || ids.has("contains_url") || ids.has("shortened_url")) tips.push("Check the actual domain before entering any personal or payment information.");
  return dedupe(tips);
}

export function analyzeText(rawText: string): AnalysisResult {
  const text = normalizeDetectionText(rawText);

  if (!text) {
    return { score: 0, level: "LOW", category: "No Suspicious Activity Detected", reasons: ["No suspicious indicators detected."], recommendations: ["No specific action is required."], preventionTips: [], isClean: true };
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

  if (matchedIds.size === 0) {
    return { score: 0, level: "LOW", category: "No Suspicious Activity Detected", reasons: ["No suspicious indicators detected."], recommendations: ["No specific action is required."], preventionTips: [], isClean: true };
  }

  if (score < 20) {
    return {
      score,
      level: "LOW",
      category: "Low Risk – Minor Signals Only",
      reasons: dedupe(reasons),
      recommendations: ["No specific action is required, but stay alert if anyone later asks for money or sensitive information."],
      preventionTips: [],
      isClean: false,
    };
  }

  return {
    score,
    level: levelFromScore(score),
    category: pickCategory(matchedIds, score),
    reasons: dedupe(reasons),
    recommendations: buildRecommendations(matchedIds),
    preventionTips: buildPreventionTips(matchedIds),
    isClean: false,
  };
}

const FREE_MAIL_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "rediffmail.com", "aol.com", "protonmail.com"];

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
          extraReasons.push(`The sender claims to be from "${brand}" but the email domain ("${domain}") does not match their official domain.`);
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

  if (extraScore === 0 && extraReasons.length === 0 && base.isClean) return base;

  const matchedIds = new Set<string>();
  const text = `${subject}\n${body}`;
  for (const indicator of INDICATORS) {
    if (indicator.test(normalizeDetectionText(text))) matchedIds.add(indicator.id);
  }

  const totalScore = Math.min(100, base.score + extraScore);
  const reasons = dedupe([...extraReasons, ...base.reasons.filter((r) => r !== "No suspicious indicators detected.")]);

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
  if (extraReasons.length > 0) recommendations.unshift("Do not trust the sender's display name alone — check the full email address carefully.");

  return {
    score: totalScore,
    level: levelFromScore(totalScore),
    category,
    reasons,
    recommendations: dedupe(recommendations),
    preventionTips: buildPreventionTips(matchedIds),
    isClean: false,
  };
}
