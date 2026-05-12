import { EmailContext, IScanner, RiskLevel, ScannerResult, Signal } from "../lib/types";
import { scoreToRiskLevel } from "../lib/scoring";

export abstract class BaseScanner implements IScanner {
  abstract readonly id: string;
  abstract readonly displayName: string;
  abstract readonly weight: number;
  readonly timeoutMs: number = 5000;

  protected abstract execute(context: EmailContext): Promise<ScannerResult>;

  async scan(context: EmailContext): Promise<ScannerResult> {
    const start = Date.now();
    try {
      const timeoutPromise = new Promise<ScannerResult>((resolve) =>
        setTimeout(
          () =>
            resolve({
              scannerId: this.id,
              displayName: this.displayName,
              score: 0,
              riskLevel: "LOW" as RiskLevel,
              signals: [],
              executionMs: Date.now() - start,
              error: `TIMEOUT_${this.timeoutMs}ms`,
            }),
          this.timeoutMs
        )
      );
      const result = await Promise.race([this.execute(context), timeoutPromise]);
      return { ...result, executionMs: Date.now() - start };
    } catch (err) {
      return {
        scannerId: this.id,
        displayName: this.displayName,
        score: 0,
        riskLevel: "LOW",
        signals: [],
        executionMs: Date.now() - start,
        error: err instanceof Error ? err.message : "UNKNOWN_ERROR",
      };
    }
  }

  protected buildResult(score: number, signals: Signal[]): ScannerResult {
    return {
      scannerId: this.id,
      displayName: this.displayName,
      score: Math.min(100, Math.max(0, Math.round(score))),
      riskLevel: scoreToRiskLevel(Math.round(score)),
      signals,
      executionMs: 0, // overwritten by scan()
    };
  }

  protected signal(
    signalId: string,
    description: string,
    severity: Signal["severity"],
    evidence: string,
    metadata?: Record<string, unknown>
  ): Signal {
    return { signalId, description, severity, evidence, metadata };
  }
}
