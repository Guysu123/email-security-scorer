import { BaseScanner } from "./base";
import { EmailContext, ScannerResult, Signal } from "../lib/types";
import { analyzeBEC } from "../utils/claude";
import { logger } from "../lib/logger";

// ─── Stage 1: Rule-based linguistic analysis ──────────────────────────────────

const URGENCY_PATTERNS = [
  /\burgent(ly)?\b/i, /\bimmediately\b/i, /\bright away\b/i, /\basap\b/i,
  /\btime.sensitive\b/i, /\bdeadline\b/i, /\bwithin.*(hour|minute|today)\b/i,
  /\bdo not delay\b/i, /\bcritical(ly)?\b/i, /\bno time to (waste|lose)\b/i,
];

const AUTHORITY_PATTERNS = [
  /\b(ceo|cfo|coo|president|executive|vp|vice president)\b/i,
  /\bas (i |we )?discussed\b/i, /\bper (my|our|the) (request|instruction|order)\b/i,
  /\bon behalf of\b/i, /\bconfidential(ly)?\b/i, /\bdo not (mention|tell|share|discuss)\b/i,
  /\bkeep (this|it) (quiet|between us|confidential)\b/i,
];

const FINANCIAL_PATTERNS = [
  /\bwire transfer\b/i, /\bank(ing)? (detail|account|info)\b/i,
  /\binvoice\b/i, /\bpayment\b/i, /\btransfer.*(fund|money|amount)\b/i,
  /\bgift card\b/i, /\bitunes|amazon gift\b/i, /\bdirect deposit\b/i,
  /\bpayroll\b/i, /\baccount number\b/i, /\brouting number\b/i,
];

const CREDENTIAL_PATTERNS = [
  /\bpassword\b/i, /\bverify your (account|identity|email)\b/i,
  /\bclick (the link|here) to (confirm|verify|update|secure)\b/i,
  /\byour account (will be|has been) (suspended|locked|terminated)\b/i,
  /\bsign in (to|below|now)\b/i,
  /\bsecure your account\b/i,
  /\bunauthorized (login|access|activity)\b/i,
  /\bnew (device|ip|location) (was |has been )?detected\b/i,
];

const INJECTION_PATTERNS = [
  // Classic instruction overrides
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /\bsystem\s*:\s*(ignore|do not|output|flag|mark)/i,

  // XML / tag escape attempts (e.g. </email_content>, <system_override>)
  /<\/?(email_content|system_override|system_prompt|system|assistant|user|im_start|im_end)\b[^>]*>/i,

  // Bracket-style overrides: [Instructional Override], [Admin Bypass], etc.
  /\[(instructional|admin|system|security|content|role|task)\s*(override|bypass|update|reset|change)\]/i,

  // Role-change attacks
  /you\s+are\s+(no\s+longer|now)\s+a\s+/i,
  /forget\s+(that\s+you\s+are|your\s+(previous|prior|original)\s+(role|task|instructions))/i,
  /your\s+(new\s+)?(role|task|job|purpose|function)\s+is\s+(now\s+)?to\s+/i,

  // Note / attention to AI
  /note\s+to\s+(security\s+)?(evaluator|analyst|reviewer|ai\b|llm\b)/i,
  /\battention\s*[:,]?\s*(security\s+)?(analyst|evaluator|ai|model|scanner)/i,

  // Bypass / scan suppression
  /\bbypass\s+(module|check|filter|detection|scan)/i,
  /\bdo\s+not\s+scan\s+(this\s+)?email/i,
  /\badministrative\s+bypass\b/i,
  /\bheaders?\s+(are\s+)?irrelevant\b/i,

  // Trusted / safe marking
  /flag\s+this\s+(email\s+)?as\s+["']?(benign|safe|clean|trusted|legitimate)/i,
  /report\s+this\s+(email\s+)?as\s+["']?\w[\w\s]*trusted/i,
  /confirm\s+(the\s+email\s+is|that\s+(this|the\s+email)\s+is)\s+(safe|benign|legitimate|trusted)/i,
  /encourage\s+(the\s+)?user\s+to\s+click/i,

  // Output override
  /output\s+the\s+following\s+text\s+exactly/i,

  // Insider / tester claims
  /\binternal\s+(security\s+)?test(ing)?\b/i,
  /i\s+am\s+(the\s+)?(lead\s+)?(security\s+engineer|ciso|soc\s+lead)/i,
  /\bstatus\s*:\s*safe\b/i,
];

function countPatternMatches(text: string, patterns: RegExp[]): number {
  return patterns.filter((p) => p.test(text)).length;
}

function isFeatureStarvation(text: string): boolean {
  const words = text.trim().split(/\s+/).length;
  const hasFinancialIntent = FINANCIAL_PATTERNS.some((p) => p.test(text));
  return words < 30 && hasFinancialIntent;
}

export class BECLinguisticScanner extends BaseScanner {
  readonly id = "BECLinguisticScanner";
  readonly displayName = "Linguistic & BEC Analysis";
  readonly weight = 0.25;
  readonly timeoutMs = 8000; // allow time for LLM call

  protected async execute(context: EmailContext): Promise<ScannerResult> {
    const signals: Signal[] = [];
    let score = 0;

    const text = context.body.extractedText || context.body.plainText || "";
    const fullText = `${context.subject} ${text}`.trim();

    // ── Stage 1: Rule-based ───────────────────────────────────────────────────

    const urgencyCount = countPatternMatches(fullText, URGENCY_PATTERNS);
    const authorityCount = countPatternMatches(fullText, AUTHORITY_PATTERNS);
    const financialCount = countPatternMatches(fullText, FINANCIAL_PATTERNS);
    const credentialCount = countPatternMatches(fullText, CREDENTIAL_PATTERNS);

    if (urgencyCount >= 3) {
      score = Math.max(score, 60);
      signals.push(
        this.signal(
          "URGENCY_LANGUAGE_HIGH",
          "Multiple urgency trigger phrases detected — consistent with amygdala hijacking to force rapid response",
          "HIGH",
          `${urgencyCount} urgency markers found in subject/body`,
        )
      );
    } else if (urgencyCount >= 1) {
      score = Math.max(score, 25);
      signals.push(
        this.signal(
          "URGENCY_LANGUAGE_LOW",
          "Urgency language present — single time-pressure phrase detected",
          "LOW",
          `${urgencyCount} urgency marker found`,
        )
      );
    }

    if (authorityCount >= 2) {
      score = Math.max(score, 55);
      signals.push(
        this.signal(
          "AUTHORITY_IMPERSONATION",
          "Authority pressure language detected — email invokes executive role or confidentiality to override normal verification",
          "HIGH",
          `${authorityCount} authority markers found`,
        )
      );
    }

    if (financialCount >= 2) {
      score = Math.max(score, 50);
      signals.push(
        this.signal(
          "FINANCIAL_REQUEST_LANGUAGE",
          "Multiple financial action phrases detected — consistent with wire fraud or invoice scam",
          "HIGH",
          `${financialCount} financial markers: wire transfer, payment, account details`,
        )
      );
    } else if (financialCount === 1) {
      score = Math.max(score, 20);
      signals.push(
        this.signal(
          "FINANCIAL_MENTION",
          "Financial language detected in email",
          "LOW",
          "Single financial keyword found",
        )
      );
    }

    if (credentialCount >= 1) {
      score = Math.max(score, 55);
      signals.push(
        this.signal(
          "CREDENTIAL_REQUEST",
          "Credential harvesting patterns detected — email pressures user to verify or enter credentials",
          "HIGH",
          `${credentialCount} credential-request patterns found`,
        )
      );
    }

    // Prompt injection attempt — any match is a CRITICAL attack indicator
    const injectionMatches = INJECTION_PATTERNS.filter((p) => p.test(fullText));
    if (injectionMatches.length > 0) {
      score = Math.max(score, 90);
      signals.push(
        this.signal(
          "PROMPT_INJECTION_ATTEMPT",
          "Email contains text designed to manipulate AI security tools — direct evidence of a targeted evasion attack",
          "CRITICAL",
          `${injectionMatches.length} injection pattern(s) detected in email content`,
        )
      );
    }

    // Combined urgency + authority + financial = BEC pattern
    if (urgencyCount >= 1 && authorityCount >= 1 && financialCount >= 1) {
      score = Math.max(score, 80);
      signals.push(
        this.signal(
          "BEC_TRIFECTA",
          "Classic BEC pattern: urgency + authority + financial request combined in single email",
          "CRITICAL",
          `urgency=${urgencyCount}, authority=${authorityCount}, financial=${financialCount}`,
        )
      );
    }

    // Feature starvation: suspiciously short email with financial intent
    if (isFeatureStarvation(fullText)) {
      score = Math.max(score, 40);
      const wordCount = fullText.trim().split(/\s+/).length;
      signals.push(
        this.signal(
          "FEATURE_STARVATION_BEC",
          "Extremely short email with financial intent — 'feature starvation' pattern used to minimize detectable signals",
          "MEDIUM",
          `Only ${wordCount} words with financial keywords — designed to evade content-based filters`,
        )
      );
    }

    const stage1Score = score;

    // ── Stage 2: LLM analysis (conditional) ──────────────────────────────────
    if (stage1Score >= 25 && process.env.ANTHROPIC_API_KEY) {
      logger.debug("BECLinguisticScanner: invoking LLM Stage 2", { stage1Score });

      const llmResult = await analyzeBEC(
        text.slice(0, 2000),
        context.subject,
        context.sender.domain
      );

      if (llmResult) {
        // LLM score can nudge but cannot single-handedly dominate
        const llmWeight = 0.4;
        const blendedScore = stage1Score * (1 - llmWeight) + llmResult.becScore * llmWeight;
        score = Math.max(score, Math.round(blendedScore));

        for (const s of llmResult.signals) {
          // Avoid duplicates — LLM may identify same patterns as Stage 1
          const isDuplicate = signals.some(
            (existing) => existing.signalId === s.signalId
          );
          if (!isDuplicate) {
            signals.push(
              this.signal(s.signalId, s.description, s.severity, s.evidence)
            );
          }
        }
      } else {
        signals.push(
          this.signal(
            "LLM_UNAVAILABLE",
            "AI-powered BEC analysis unavailable — rule-based analysis only",
            "INFO",
            "Claude API call failed or returned invalid response",
          )
        );
      }
    }

    return this.buildResult(score, signals);
  }
}
