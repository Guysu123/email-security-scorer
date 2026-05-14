import Anthropic from "@anthropic-ai/sdk";
import { logger } from "../lib/logger";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

function xmlEscape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export interface BECAnalysis {
  becScore: number;        // 0–100
  signals: Array<{
    signalId: string;
    description: string;
    evidence: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  }>;
}

const RESPONSE_SCHEMA = `{
  "becScore": <integer 0-100>,
  "signals": [
    {
      "signalId": "<SCREAMING_SNAKE_CASE>",
      "description": "<one sentence>",
      "evidence": "<specific text excerpt, max 100 chars>",
      "severity": "<CRITICAL|HIGH|MEDIUM|LOW>"
    }
  ]
}`;

export async function analyzeBEC(
  plainText: string,
  subject: string,
  senderDomain: string
): Promise<BECAnalysis | null> {
  // Limit input to control costs and reduce injection surface
  const truncatedText = plainText.slice(0, 2000);

  const systemPrompt = `You are a cybersecurity analyst specializing in Business Email Compromise (BEC) detection. Analyze the email data provided by the user and respond ONLY with valid JSON matching the schema. Do not include any explanation outside the JSON.

RESPONSE SCHEMA:
${RESPONSE_SCHEMA}

SCORING GUIDE:
- 0-20: No BEC indicators
- 21-40: Mild linguistic pressure
- 41-60: Clear urgency/authority patterns
- 61-80: Strong BEC indicators (multiple patterns)
- 81-100: Definitive BEC (urgency + authority + financial + time pressure)

SIGNAL IDs to use (pick relevant ones):
URGENCY_LANGUAGE_HIGH, AUTHORITY_IMPERSONATION, WIRE_TRANSFER_REQUEST,
CREDENTIAL_REQUEST, FEATURE_STARVATION_BEC, AI_GENERATED_DICTION,
GIFT_CARD_REQUEST, PAYROLL_DIVERSION, VENDOR_IMPERSONATION,
UNUSUAL_PAYMENT_REQUEST, EMOTIONAL_MANIPULATION

Respond with JSON only.`;

  const userMessage =
    `<email_subject>${xmlEscape(subject.slice(0, 200))}</email_subject>\n` +
    `<email_sender_domain>${xmlEscape(senderDomain)}</email_sender_domain>\n` +
    `<email_content>${xmlEscape(truncatedText)}</email_content>`;

  try {
    const response = await client.messages.create({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 400,
      system: systemPrompt,
      messages: [{ role: "user", content: userMessage }],
    });

    const rawText = response.content[0].type === "text" ? response.content[0].text : "";

    // Extract JSON from response (defensive — LLM might add text around it)
    const jsonMatch = rawText.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      logger.warn("BEC LLM: no JSON found in response");
      return null;
    }

    const parsed = JSON.parse(jsonMatch[0]) as unknown;
    return validateBECAnalysis(parsed);
  } catch (err) {
    logger.warn("BEC LLM call failed", { error: String(err) });
    return null;
  }
}

function validateBECAnalysis(raw: unknown): BECAnalysis | null {
  if (typeof raw !== "object" || raw === null) return null;
  const obj = raw as Record<string, unknown>;

  const score = typeof obj.becScore === "number" ? obj.becScore : null;
  if (score === null || score < 0 || score > 100) return null;

  const signals = Array.isArray(obj.signals) ? obj.signals : [];
  const validSignals = signals
    .filter(
      (s): s is Record<string, unknown> =>
        typeof s === "object" &&
        s !== null &&
        typeof (s as Record<string, unknown>).signalId === "string"
    )
    .map((s) => ({
      signalId: String(s.signalId).replace(/[^A-Z0-9_]/g, "").slice(0, 50),
      description: String(s.description ?? "").slice(0, 200),
      evidence: String(s.evidence ?? "").slice(0, 100),
      severity: (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(String(s.severity))
        ? String(s.severity)
        : "MEDIUM") as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    }));

  return { becScore: Math.round(score), signals: validSignals };
}
