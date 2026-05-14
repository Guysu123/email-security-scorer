import { TestResult } from "../types";

export function printReport(results: TestResult[], totalMs: number): void {
  const passed = results.filter(r => r.passed).length;
  const failed = results.filter(r => !r.passed).length;

  const COL_ID    = 30;
  const COL_SCORE =  6;
  const COL_RISK  = 10;
  const COL_STATUS = 20;

  const line = (char: string, len: number) => char.repeat(len);
  const pad  = (s: string, n: number) => s.padEnd(n).slice(0, n);

  const width = COL_ID + COL_SCORE + COL_RISK + COL_STATUS + 6;

  console.log(`\nTest Batch Results — ${new Date().toISOString().replace("T", " ").slice(0, 16)}`);
  console.log(line("═", width));
  console.log(
    " " + pad("ID", COL_ID) +
    pad("Score", COL_SCORE) +
    pad("Risk", COL_RISK) +
    "Status"
  );
  console.log(line("─", width));

  for (const r of results) {
    const score  = r.error ? "ERR" : String(r.score);
    const risk   = r.error ? "—"   : r.riskLevel;
    let   status: string;

    if (r.error) {
      status = `✗ ERROR  ${r.error}`;
    } else if (r.passed) {
      status = "✓ PASS";
    } else {
      status = `✗ FAIL  expected [${r.expected.scoreMin},${r.expected.scoreMax}]`;
    }

    console.log(
      " " + pad(r.id, COL_ID) +
      pad(score, COL_SCORE) +
      pad(risk, COL_RISK) +
      status
    );
  }

  console.log(line("─", width));
  console.log(
    ` Results: ${passed}/${results.length} passed  |  ${failed} failed  |  Total time: ${totalMs.toLocaleString()}ms`
  );
  console.log("");
}
