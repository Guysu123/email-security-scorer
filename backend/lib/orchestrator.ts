import { EmailContext, IScanner, ScannerResult } from "./types";
import { aggregate, AggregatedScore, scoreToRiskLevel } from "./scoring";
import { logger } from "./logger";
import { HeaderAuthScanner } from "../scanners/HeaderAuthScanner";
import { BECLinguisticScanner } from "../scanners/BECLinguisticScanner";
import { URLScanner } from "../scanners/URLScanner";
import { SenderReputationScanner } from "../scanners/SenderReputationScanner";
import { ContentStructureScanner } from "../scanners/ContentStructureScanner";

const SCANNERS: IScanner[] = [
  new HeaderAuthScanner(),
  new BECLinguisticScanner(),
  new URLScanner(),
  new SenderReputationScanner(),
  new ContentStructureScanner(),
];

export interface OrchestratorResult extends AggregatedScore {
  scannerResults: ScannerResult[];
  partialAnalysis: boolean;
  totalExecutionMs: number;
}

export async function runAnalysis(context: EmailContext): Promise<OrchestratorResult> {
  const start = Date.now();

  const settled = await Promise.allSettled(
    SCANNERS.map((scanner) => scanner.scan(context))
  );

  const scannerResults: ScannerResult[] = settled.map((outcome, i) => {
    if (outcome.status === "fulfilled") {
      return outcome.value;
    }
    // Promise itself rejected (scanner.scan() shouldn't throw — base class catches —
    // but this is a safety net)
    const scanner = SCANNERS[i];
    logger.error("Scanner promise rejected", { scannerId: scanner.id, reason: String(outcome.reason) });
    return {
      scannerId: scanner.id,
      displayName: scanner.displayName,
      score: 0,
      riskLevel: scoreToRiskLevel(0),
      signals: [],
      executionMs: 0,
      error: "PROMISE_REJECTED",
    };
  });

  const partialAnalysis = scannerResults.some((r) => !!r.error);

  const scoredScanners = scannerResults.map((result, i) => ({
    result,
    weight: SCANNERS[i].weight,
  }));

  const aggregated = aggregate(scoredScanners);
  const totalExecutionMs = Date.now() - start;

  logger.info("Analysis complete", {
    finalScore: aggregated.finalScore,
    riskLevel: aggregated.riskLevel,
    partialAnalysis,
    totalExecutionMs,
  });

  return {
    ...aggregated,
    scannerResults,
    partialAnalysis,
    totalExecutionMs,
  };
}
