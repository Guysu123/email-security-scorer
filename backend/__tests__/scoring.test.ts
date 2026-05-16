import { describe, it, expect } from "vitest";
import { aggregate, scoreToRiskLevel } from "../lib/scoring";
import type { ScannerResult } from "../lib/types";

function makeScanner(
  id: string,
  score: number,
  signals: { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" }[] = [],
  weight = 0.20
): { result: ScannerResult; weight: number } {
  return {
    weight,
    result: {
      scannerId: id,
      displayName: id,
      score,
      riskLevel: scoreToRiskLevel(score),
      signals: signals.map((s, i) => ({
        signalId: `SIG_${i}`,
        description: "test signal",
        severity: s.severity,
        evidence: "test evidence",
      })),
      executionMs: 1,
    },
  };
}

describe("scoreToRiskLevel", () => {
  it("0  → LOW",      () => expect(scoreToRiskLevel(0)).toBe("LOW"));
  it("34 → LOW",      () => expect(scoreToRiskLevel(34)).toBe("LOW"));
  it("35 → MEDIUM",   () => expect(scoreToRiskLevel(35)).toBe("MEDIUM"));
  it("54 → MEDIUM",   () => expect(scoreToRiskLevel(54)).toBe("MEDIUM"));
  it("55 → HIGH",     () => expect(scoreToRiskLevel(55)).toBe("HIGH"));
  it("69 → HIGH",     () => expect(scoreToRiskLevel(69)).toBe("HIGH"));
  it("70 → CRITICAL", () => expect(scoreToRiskLevel(70)).toBe("CRITICAL"));
  it("100 → CRITICAL",() => expect(scoreToRiskLevel(100)).toBe("CRITICAL"));
});

describe("aggregate — weighted average", () => {
  it("computes weighted average with equal weights", () => {
    const scanners = [makeScanner("A", 80), makeScanner("B", 20)];
    const r = aggregate(scanners);
    expect(r.finalScore).toBe(50);
  });

  it("returns 0 for all-zero scanners", () => {
    const r = aggregate([makeScanner("A", 0), makeScanner("B", 0)]);
    expect(r.finalScore).toBe(0);
    expect(r.riskLevel).toBe("LOW");
  });
});

describe("aggregate — CRITICAL signal override", () => {
  it("lifts score floor to 70 when any signal is CRITICAL", () => {
    const r = aggregate([makeScanner("A", 10, [{ severity: "CRITICAL" }])]);
    expect(r.finalScore).toBeGreaterThanOrEqual(70);
    expect(r.riskLevel).toBe("CRITICAL");
  });

  it("does not lift floor when all signals are HIGH", () => {
    const r = aggregate([makeScanner("A", 50, [{ severity: "HIGH" }])]);
    expect(r.finalScore).toBeLessThan(70);
  });
});

describe("aggregate — corroboration boost", () => {
  it("applies 1.2× boost when ≥3 scanners score > 50", () => {
    const scanners = [
      makeScanner("A", 60),
      makeScanner("B", 60),
      makeScanner("C", 60),
    ];
    const r = aggregate(scanners);
    // base = 60, boosted = 60 * 1.2 = 72
    expect(r.finalScore).toBeGreaterThan(60);
    expect(r.riskLevel).toBe("CRITICAL");
  });

  it("does not apply boost with only 2 high-scoring scanners", () => {
    const scanners = [makeScanner("A", 60), makeScanner("B", 60)];
    const r = aggregate(scanners);
    expect(r.finalScore).toBe(60);
  });
});

describe("aggregate — topSignals ordering", () => {
  it("puts CRITICAL signals before HIGH signals in topSignals", () => {
    const scanners = [
      makeScanner("A", 60, [{ severity: "HIGH" }]),
      makeScanner("B", 75, [{ severity: "CRITICAL" }]),
    ];
    const r = aggregate(scanners);
    expect(r.topSignals[0].severity).toBe("CRITICAL");
  });
});
