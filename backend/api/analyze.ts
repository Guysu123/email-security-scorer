import type { VercelRequest, VercelResponse } from "@vercel/node";
import { AnalyzeRequest, AnalyzeResponse, ErrorResponse, ScannerResultPublic } from "../lib/types";
import { sanitize } from "../lib/sanitizer";
import { runAnalysis } from "../lib/orchestrator";
import { logger } from "../lib/logger";
import { escapeHtml } from "../utils/html";
import crypto from "crypto";

const BACKEND_VERSION = "1.0.0";
const MAX_BODY_BYTES = 500 * 1024;

// ─── Simple in-memory rate limiting ──────────────────────────────────────────
// Resets on cold start — acceptable for this deployment scale
const rateLimitMap = new Map<string, { count: number; windowStart: number }>();
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const RATE_LIMIT_MAX = 60;

function isRateLimited(key: string): boolean {
  const now = Date.now();
  const entry = rateLimitMap.get(key);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateLimitMap.set(key, { count: 1, windowStart: now });
    return false;
  }
  entry.count++;
  return entry.count > RATE_LIMIT_MAX;
}

// ─── Auth verification ────────────────────────────────────────────────────────

function verifyAuth(req: VercelRequest): boolean {
  const secret = process.env.ADDON_API_SECRET;
  if (!secret) {
    logger.warn("ADDON_API_SECRET not configured");
    return false;
  }
  const authHeader = req.headers.authorization ?? "";
  if (!authHeader.startsWith("Bearer ")) return false;
  const provided = authHeader.slice(7);
  // Timing-safe comparison
  try {
    return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(secret));
  } catch {
    return false;
  }
}

// ─── Request validation ───────────────────────────────────────────────────────

function validateRequest(body: unknown): body is AnalyzeRequest {
  if (typeof body !== "object" || body === null) return false;
  const b = body as Record<string, unknown>;
  return (
    typeof b.rawHeaders === "string" &&
    typeof b.sender === "object" && b.sender !== null &&
    typeof (b.sender as Record<string, unknown>).emailAddress === "string" &&
    typeof b.subject === "string" &&
    typeof b.envelope === "object" && b.envelope !== null &&
    typeof b.requestMetadata === "object" && b.requestMetadata !== null
  );
}

// ─── Handler ──────────────────────────────────────────────────────────────────

export default async function handler(
  req: VercelRequest,
  res: VercelResponse
): Promise<void> {
  const requestId = crypto.randomUUID();

  // Method check
  if (req.method !== "POST") {
    res.status(405).json({ error: "METHOD_NOT_ALLOWED", message: "Use POST", requestId });
    return;
  }

  // Auth
  if (!verifyAuth(req)) {
    logger.warn("Unauthorized request", { requestId });
    res.status(401).json({ error: "UNAUTHORIZED", message: "Invalid or missing API key", requestId });
    return;
  }

  // Rate limiting keyed on auth token hash (don't log the token itself)
  const authToken = (req.headers.authorization ?? "").slice(7);
  const tokenHash = crypto.createHash("sha256").update(authToken).digest("hex").slice(0, 16);
  if (isRateLimited(tokenHash)) {
    res.status(429).json({ error: "RATE_LIMITED", message: "Too many requests — max 60/hour", requestId });
    return;
  }

  // Body size guard
  const rawBody = JSON.stringify(req.body);
  if (Buffer.byteLength(rawBody, "utf8") > MAX_BODY_BYTES) {
    res.status(413).json({ error: "PAYLOAD_TOO_LARGE", message: "Request body exceeds 500KB limit", requestId });
    return;
  }

  // Validate shape
  if (!validateRequest(req.body)) {
    res.status(400).json({
      error: "VALIDATION_ERROR",
      message: "Request body missing required fields",
      requestId,
    } as ErrorResponse);
    return;
  }

  const analysisId = crypto.randomUUID();
  const analysisStart = Date.now();

  try {
    // Sanitize: untrusted AnalyzeRequest → safe EmailContext
    const context = sanitize(req.body as AnalyzeRequest);

    // Run all scanners
    const result = await runAnalysis(context);

    // Build public scanner results (sanitize evidence fields)
    const scannerResults: ScannerResultPublic[] = result.scannerResults.map((r, i) => {
      const scannerWeight = [0.30, 0.25, 0.20, 0.15, 0.10][i] ?? 0;
      return {
        scannerId: r.scannerId,
        displayName: r.displayName,
        score: r.score,
        weight: scannerWeight,
        weightedContribution: Math.round(r.score * scannerWeight * 10) / 10,
        riskLevel: r.riskLevel,
        signals: r.signals.map((s) => ({
          signalId: s.signalId,
          description: s.description,
          severity: s.severity,
          evidence: escapeHtml(s.evidence),
        })),
        executionMs: r.executionMs,
        error: r.error,
      };
    });

    const response: AnalyzeResponse = {
      requestId,
      analysisId,
      finalScore: result.finalScore,
      riskLevel: result.riskLevel,
      verdict: result.verdict,
      scannerResults,
      topSignals: result.topSignals,
      partialAnalysis: result.partialAnalysis,
      metadata: {
        totalExecutionMs: Date.now() - analysisStart,
        scannersRun: result.scannerResults.length,
        backendVersion: BACKEND_VERSION,
        timestamp: new Date().toISOString(),
      },
    };

    res.status(200).json(response);
  } catch (err) {
    const message = err instanceof Error ? err.message : "INTERNAL_ERROR";
    logger.error("Analysis failed", { requestId, analysisId, error: message });

    if (message === "REQUEST_TOO_LARGE") {
      res.status(413).json({ error: "PAYLOAD_TOO_LARGE", message: "Email content exceeds size limits", requestId });
      return;
    }

    res.status(500).json({
      error: "INTERNAL_ERROR",
      message: "Analysis failed — please retry",
      requestId,
    } as ErrorResponse);
  }
}
