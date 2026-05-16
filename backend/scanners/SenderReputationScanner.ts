import { BaseScanner } from "./base";
import { EmailContext, ScannerResult, Signal } from "../lib/types";
import { checkTyposquat, checkSubdomainConfusion, BRAND_DOMAINS } from "../utils/punycode";
import { escapeHtml } from "../utils/html";
import { getDomainAgeDays } from "../utils/domainAge";

const FREE_PROVIDERS = new Set([
  "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
  "aol.com", "icloud.com", "protonmail.com", "tutanota.com", "yandex.com",
  "mail.com", "zoho.com", "gmx.com", "inbox.com",
]);

const FINANCIAL_KEYWORDS = [
  /\bwire transfer\b/i, /\bpayment\b/i, /\binvoice\b/i, /\baccount (number|detail)\b/i,
  /\bank(ing)?\b/i, /\bgift card\b/i, /\bdirect deposit\b/i, /\bpayroll\b/i,
];

// Character-level visual substitutions attackers use to create lookalike domains
const VISUAL_SUBS: [RegExp, string][] = [
  [/0/g, "o"], [/1/g, "l"], [/rn/g, "m"], [/vv/g, "w"],
  [/5/g, "s"], [/3/g, "e"], [/4/g, "a"], [/6/g, "g"],
];

function hasFinancialContext(context: EmailContext): boolean {
  const text = `${context.subject} ${context.body.extractedText}`;
  return FINANCIAL_KEYWORDS.some((p) => p.test(text));
}

function normalizeDomainChars(domain: string): string {
  let n = domain.toLowerCase();
  for (const [from, to] of VISUAL_SUBS) n = n.replace(from, to);
  return n;
}

export class SenderReputationScanner extends BaseScanner {
  readonly id = "SenderReputationScanner";
  readonly displayName = "Sender Reputation";
  readonly weight = 0.15;
  readonly timeoutMs = 7000; // accommodates RDAP lookup (~4s budget)

  protected async execute(context: EmailContext): Promise<ScannerResult> {
    const signals: Signal[] = [];
    let score = 0;

    const { domain, replyTo, replyToDomain, displayName, emailAddress } = context.sender;

    // ── Display name spoofing ─────────────────────────────────────────────────
    // Display name claims to be a known brand but From domain doesn't match
    for (const brand of BRAND_DOMAINS) {
      const brandName = brand.split(".")[0];
      const displayNameLower = displayName.toLowerCase();
      if (
        displayNameLower.includes(brandName) &&
        !domain.endsWith(brand) &&
        !domain.endsWith("." + brand)
      ) {
        score = Math.max(score, 65);
        signals.push(
          this.signal(
            "DISPLAY_NAME_SPOOFING",
            `Display name claims to be "${brandName}" but sending domain doesn't match`,
            "HIGH",
            escapeHtml(`Display: "${displayName}" | From domain: ${domain}`),
          )
        );
        break;
      }
    }

    // ── Sender domain lookalike ───────────────────────────────────────────────
    const confused = checkSubdomainConfusion(domain);
    if (confused) {
      score = Math.max(score, 80);
      signals.push(
        this.signal(
          "SUBDOMAIN_CONFUSION_SENDER",
          `Sender domain embeds "${confused}" as a subdomain to appear legitimate`,
          "HIGH",
          escapeHtml(`${domain} → ${confused} appears as subdomain`),
        )
      );
    }

    const typo = checkTyposquat(domain);
    if (typo.isTyposquat && typo.matchedBrand) {
      score = Math.max(score, 70);
      signals.push(
        this.signal(
          "LOOKALIKE_DOMAIN",
          `Sender domain is a probable typosquat of "${typo.matchedBrand}" (edit distance: ${typo.distance})`,
          "HIGH",
          escapeHtml(`${domain} ≈ ${typo.matchedBrand}`),
        )
      );
    }

    // ── Reply-To mismatch ─────────────────────────────────────────────────────
    if (replyTo && replyToDomain && replyToDomain !== domain) {
      const isReplyFree = FREE_PROVIDERS.has(replyToDomain);
      const severity = isReplyFree ? "HIGH" : "MEDIUM";
      score = Math.max(score, isReplyFree ? 65 : 40);
      signals.push(
        this.signal(
          "REPLY_TO_MISMATCH",
          `Reply-To domain (${replyToDomain}) differs from sender domain (${domain}) — responses will go to a different party`,
          severity,
          escapeHtml(`From: ${emailAddress} | Reply-To: ${replyTo}`),
        )
      );
    }

    // ── Free provider + financial context ────────────────────────────────────
    if (FREE_PROVIDERS.has(domain) && hasFinancialContext(context)) {
      score = Math.max(score, 50);
      signals.push(
        this.signal(
          "FREE_PROVIDER_FINANCIAL_REQUEST",
          "Email from free provider makes financial request — business transactions from personal accounts is a strong BEC indicator",
          "HIGH",
          `Sender domain: ${domain} (free provider) with financial keywords detected`,
        )
      );
    } else if (FREE_PROVIDERS.has(domain)) {
      score = Math.max(score, 10);
      signals.push(
        this.signal(
          "FREE_PROVIDER_SENDER",
          "Email sent from a free consumer email provider",
          "INFO",
          `Sender domain: ${domain}`,
        )
      );
    }

    // ── From/To address comparison ────────────────────────────────────────────
    // Self-sent emails (from == to) are a known social engineering tactic
    const toHeader = context.headers.get("to") ?? "";
    if (toHeader.toLowerCase().includes(emailAddress.toLowerCase())) {
      score = Math.max(score, 35);
      signals.push(
        this.signal(
          "SELF_SENT_EMAIL",
          "Email appears to be sent from the same address as the recipient — common in sextortion and account-compromise scams",
          "MEDIUM",
          escapeHtml(`From: ${emailAddress} appears in To: header`),
        )
      );
    }

    // ── Domain age (RDAP) ─────────────────────────────────────────────────────
    // Skip free consumer providers — their domain age is irrelevant to sender risk.
    if (!FREE_PROVIDERS.has(domain)) {
      const ageDays = await getDomainAgeDays(domain);
      if (ageDays !== null && ageDays < 30) {
        score = Math.max(score, 75);
        signals.push(
          this.signal(
            "NEWLY_REGISTERED_DOMAIN",
            `Sender domain is only ${ageDays} day${ageDays !== 1 ? "s" : ""} old — newly registered domains account for the majority of targeted phishing infrastructure`,
            "CRITICAL",
            escapeHtml(`${domain} registered ${ageDays} day${ageDays !== 1 ? "s" : ""} ago`),
          )
        );
      } else if (ageDays !== null && ageDays < 90) {
        score = Math.max(score, 45);
        signals.push(
          this.signal(
            "YOUNG_DOMAIN",
            `Sender domain is less than 90 days old — recently registered domains are frequently associated with phishing campaigns`,
            "HIGH",
            escapeHtml(`${domain} registered ${ageDays} days ago`),
          )
        );
      }
    }

    return this.buildResult(score, signals);
  }
}
