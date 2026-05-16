import type { VercelRequest, VercelResponse } from "@vercel/node";
import { RiskLevel } from "../lib/types";
import { logger } from "../lib/logger";
import crypto from "crypto";

// ─── Auth (same pattern as analyze.ts) ───────────────────────────────────────

function verifyAuth(req: VercelRequest): boolean {
  const secret = process.env.ADDON_API_SECRET;
  if (!secret) {
    logger.warn("ADDON_API_SECRET not configured");
    return false;
  }
  const authHeader = req.headers.authorization ?? "";
  if (!authHeader.startsWith("Bearer ")) return false;
  const provided = authHeader.slice(7);
  try {
    return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(secret));
  } catch {
    return false;
  }
}

// ─── Validation ───────────────────────────────────────────────────────────────

interface FeedbackRequest {
  messageId: string;
  originalScore: number;
  originalRisk: RiskLevel;
  suggestedRisk: RiskLevel | null;
  comment: string;
}

const VALID_RISK_LEVELS = new Set<string>(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);

function validateRequest(body: unknown): body is FeedbackRequest {
  if (typeof body !== "object" || body === null) return false;
  const b = body as Record<string, unknown>;
  return (
    typeof b.messageId === "string" && b.messageId.length > 0 &&
    typeof b.originalScore === "number" &&
    typeof b.originalRisk === "string" && VALID_RISK_LEVELS.has(b.originalRisk) &&
    (b.suggestedRisk === null || (typeof b.suggestedRisk === "string" && VALID_RISK_LEVELS.has(b.suggestedRisk))) &&
    typeof b.comment === "string"
  );
}

// ─── Handler ──────────────────────────────────────────────────────────────────

export default function handler(req: VercelRequest, res: VercelResponse): void {
  const requestId = crypto.randomUUID();

  if (req.method !== "POST") {
    res.status(405).json({ error: "METHOD_NOT_ALLOWED", requestId });
    return;
  }

  if (!verifyAuth(req)) {
    logger.warn("Unauthorized feedback request", { requestId });
    res.status(401).json({ error: "UNAUTHORIZED", requestId });
    return;
  }

  if (!validateRequest(req.body)) {
    res.status(400).json({ error: "VALIDATION_ERROR", message: "Missing or invalid fields", requestId });
    return;
  }

  const { messageId, originalScore, originalRisk, suggestedRisk, comment } = req.body;

  logger.info("Score dispute received", {
    requestId,
    messageId,
    originalScore,
    originalRisk,
    suggestedRisk,
    comment: comment.slice(0, 500),
  });

  res.status(200).json({ ok: true, requestId });
}
