import { RiskLevel, ScannerResult, Signal, Severity } from "./types";

interface ScoredScanner {
  result: ScannerResult;
  weight: number;
}

export interface AggregatedScore {
  finalScore: number;
  riskLevel: RiskLevel;
  verdict: string;
  topSignals: Array<{ signalId: string; description: string; severity: Severity; scannerId: string }>;
}

// ─── Risk level mapping ───────────────────────────────────────────────────────

export function scoreToRiskLevel(score: number): RiskLevel {
  if (score >= 70) return "CRITICAL";
  if (score >= 55) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
}

// ─── Verdict templates ────────────────────────────────────────────────────────

const VERDICT_TEMPLATES: Record<RiskLevel, Record<string, string>> = {
  CRITICAL: {
    DMARC_FAIL_WIRE_TRANSFER:
      "Authentication completely fails and urgent financial language detected — consistent with CEO fraud.",
    DMARC_FAIL:
      "Email authentication completely fails — this message cannot be verified as coming from the claimed sender.",
    HOMOGRAPH_ATTACK:
      "Domain uses look-alike Unicode characters designed to visually impersonate a trusted brand.",
    BEC_AUTHORITY:
      "Combines authority impersonation with urgency to pressure immediate action — hallmark of Business Email Compromise.",
    DEFAULT: "Multiple critical threat indicators detected. Exercise extreme caution before taking any action.",
  },
  HIGH: {
    DKIM_FAIL: "Email signature verification failed — message may have been tampered with in transit.",
    URGENCY_LANGUAGE: "Strong urgency and pressure language detected alongside sender anomalies.",
    LOOKALIKE_DOMAIN:
      "Sender domain is a near-identical misspelling of a trusted brand — likely spoofing attack.",
    DEFAULT: "Significant threat indicators detected. Verify the sender through a separate channel before responding.",
  },
  MEDIUM: {
    REPLY_TO_MISMATCH:
      "Reply-To address differs from the sender — responses will go to a different party than expected.",
    FREE_PROVIDER: "Unusual combination of free email provider with financial or credential request.",
    DEFAULT: "Some suspicious patterns detected. Proceed with caution and verify sender identity if uncertain.",
  },
  LOW: {
    DEFAULT: "No significant threats detected. Standard caution applies.",
  },
};

function selectVerdict(riskLevel: RiskLevel, topSignalIds: string[]): string {
  const templates = VERDICT_TEMPLATES[riskLevel];
  for (const id of topSignalIds) {
    if (id.includes("DMARC_FAIL") && id.includes("WIRE_TRANSFER"))
      return templates["DMARC_FAIL_WIRE_TRANSFER"] ?? templates["DEFAULT"];
    if (id.includes("HOMOGRAPH")) return templates["HOMOGRAPH_ATTACK"] ?? templates["DEFAULT"];
    if (id.includes("DMARC_FAIL")) return templates["DMARC_FAIL"] ?? templates["DEFAULT"];
    if (id.includes("DKIM_FAIL")) return templates["DKIM_FAIL"] ?? templates["DEFAULT"];
    if (id.includes("AUTHORITY") || id.includes("BEC")) return templates["BEC_AUTHORITY"] ?? templates["DEFAULT"];
    if (id.includes("URGENCY")) return templates["URGENCY_LANGUAGE"] ?? templates["DEFAULT"];
    if (id.includes("LOOKALIKE")) return templates["LOOKALIKE_DOMAIN"] ?? templates["DEFAULT"];
    if (id.includes("REPLY_TO")) return templates["REPLY_TO_MISMATCH"] ?? templates["DEFAULT"];
    if (id.includes("FREE_PROVIDER")) return templates["FREE_PROVIDER"] ?? templates["DEFAULT"];
  }
  return templates["DEFAULT"] ?? "Analysis complete.";
}

// ─── Aggregation ──────────────────────────────────────────────────────────────

export function aggregate(scanners: ScoredScanner[]): AggregatedScore {
  const completedScanners = scanners.filter((s) => !s.result.error || s.result.score > 0);

  // Weighted base score
  const totalWeight = completedScanners.reduce((sum, s) => sum + s.weight, 0);
  let baseScore = totalWeight > 0
    ? completedScanners.reduce((sum, s) => sum + s.result.score * s.weight, 0) / totalWeight
    : 0;

  // Collect all signals
  const allSignals = completedScanners.flatMap((s) =>
    s.result.signals.map((sig) => ({ ...sig, scannerId: s.result.scannerId }))
  );

  // Critical signal override: any CRITICAL signal lifts floor to 70
  const hasCritical = allSignals.some((sig) => sig.severity === "CRITICAL");
  if (hasCritical) {
    baseScore = Math.max(baseScore, 70);
  }

  // Amplification: ≥3 scanners agree score > 50 → strong corroboration boost
  const highScoringCount = completedScanners.filter((s) => s.result.score > 50).length;
  if (highScoringCount >= 3) {
    baseScore = Math.min(100, baseScore * 1.2);
  }

  // Weak corroboration: 2+ independent scanners produce HIGH/CRITICAL signals → floor at MEDIUM
  const scannersWithHighSignals = completedScanners.filter((s) =>
    s.result.signals.some((sig) => sig.severity === "CRITICAL" || sig.severity === "HIGH")
  ).length;
  if (scannersWithHighSignals >= 2) {
    baseScore = Math.max(baseScore, 40);
  }

  // Attenuation: strong auth pass + clean language → reduce false positives
  const headerScanner = completedScanners.find((s) => s.result.scannerId === "HeaderAuthScanner");
  const becScanner = completedScanners.find((s) => s.result.scannerId === "BECLinguisticScanner");
  if (
    headerScanner && headerScanner.result.score < 10 &&
    becScanner && becScanner.result.score < 20
  ) {
    baseScore = baseScore * 0.8;
  }

  const finalScore = Math.min(100, Math.max(0, Math.round(baseScore)));
  const riskLevel = scoreToRiskLevel(finalScore);

  // Top signals: sort by severity then score contribution
  const severityOrder: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const topSignals = [...allSignals]
    .sort((a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0))
    .slice(0, 5)
    .map((s) => ({
      signalId: s.signalId,
      description: s.description,
      severity: s.severity,
      scannerId: s.scannerId,
    }));

  const verdict = selectVerdict(riskLevel, topSignals.map((s) => s.signalId));

  return { finalScore, riskLevel, verdict, topSignals };
}
