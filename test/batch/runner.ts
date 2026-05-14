import { phishingCases } from "./cases/phishing";
import { becCases }      from "./cases/bec";
import { benignCases }   from "./cases/benign";
import { printReport }   from "./report";
import { encryptPayload } from "../encrypt";
import { TestCase, TestResult, AnalyzeResponse, RiskLevel } from "../types";

const API_URL        = process.env.TEST_API_URL   || "http://localhost:3000";
const API_TOKEN      = process.env.TEST_API_TOKEN?.trim();
const ENCRYPTION_KEY = process.env.PAYLOAD_ENCRYPTION_KEY?.trim();

if (!API_TOKEN) {
  console.error("ERROR: TEST_API_TOKEN is not set.");
  process.exit(1);
}

if (ENCRYPTION_KEY) {
  console.log("Encryption: enabled (PAYLOAD_ENCRYPTION_KEY is set)");
} else {
  console.log("Encryption: disabled (sending plain JSON)");
}

function scoreToRiskLevel(score: number): RiskLevel {
  if (score >= 70) return "CRITICAL";
  if (score >= 55) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
}

function validateCase(tc: TestCase): void {
  const minTier = scoreToRiskLevel(tc.expect.scoreMin);
  const maxTier = scoreToRiskLevel(tc.expect.scoreMax);
  if (minTier !== maxTier) {
    throw new Error(
      `Test case ${tc.id}: scoreMin (${tc.expect.scoreMin} → ${minTier}) and scoreMax (${tc.expect.scoreMax} → ${maxTier}) span different risk tiers. Fix the range.`
    );
  }
}

async function runCase(tc: TestCase): Promise<TestResult> {
  const start = Date.now();
  try {
    const plainJson = JSON.stringify(tc.email);
    const requestBody = ENCRYPTION_KEY
      ? JSON.stringify({ enc: encryptPayload(plainJson, ENCRYPTION_KEY) })
      : plainJson;

    const res = await fetch(`${API_URL}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${API_TOKEN}`,
      },
      body: requestBody,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      return {
        id: tc.id,
        category: tc.category,
        score: 0,
        riskLevel: "LOW",
        expected: tc.expect,
        passed: false,
        error: `HTTP ${res.status}: ${text.slice(0, 120)}`,
        executionMs: Date.now() - start,
      };
    }

    const data = await res.json() as AnalyzeResponse;
    const passed =
      data.finalScore >= tc.expect.scoreMin &&
      data.finalScore <= tc.expect.scoreMax;

    return {
      id: tc.id,
      category: tc.category,
      score: data.finalScore,
      riskLevel: data.riskLevel,
      expected: tc.expect,
      passed,
      executionMs: Date.now() - start,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      id: tc.id,
      category: tc.category,
      score: 0,
      riskLevel: "LOW",
      expected: tc.expect,
      passed: false,
      error: msg.slice(0, 120),
      executionMs: Date.now() - start,
    };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main(): Promise<void> {
  const allCases: TestCase[] = [...phishingCases, ...becCases, ...benignCases];

  // Validate all test definitions before hitting the API
  for (const tc of allCases) {
    validateCase(tc);
  }

  console.log(`\nRunning ${allCases.length} test cases against ${API_URL} ...\n`);

  const results: TestResult[] = [];
  const start = Date.now();

  for (let i = 0; i < allCases.length; i++) {
    const tc = allCases[i];
    process.stdout.write(`[${i + 1}/${allCases.length}] ${tc.id} ... `);
    const result = await runCase(tc);
    results.push(result);
    console.log(result.error ? "ERROR" : result.passed ? "PASS" : "FAIL");

    if (i < allCases.length - 1) {
      await sleep(500);
    }
  }

  const totalMs = Date.now() - start;
  printReport(results, totalMs);

  const anyFailed = results.some(r => !r.passed);
  process.exit(anyFailed ? 1 : 0);
}

main();
