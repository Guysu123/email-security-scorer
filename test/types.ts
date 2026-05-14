export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Severity  = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface AnalyzeRequest {
  envelope: {
    messageId: string;
    gmailThreadId: string;
    receivedTimestamp: string;
  };
  rawHeaders: string;
  sender: {
    displayName: string;
    emailAddress: string;
    replyTo: string | null;
  };
  subject: string;
  body: {
    plainText: string | null;
    htmlContent: string | null;
  };
  attachments: AttachmentMeta[];
  requestMetadata: {
    addonVersion: string;
    requestId: string;
    timestamp: string;
  };
}

export interface AttachmentMeta {
  filename: string;
  mimeType: string;
  sizeBytes: number;
}

export interface AnalyzeResponse {
  requestId: string;
  analysisId: string;
  finalScore: number;
  riskLevel: RiskLevel;
  verdict: string;
  scannerResults: Array<{
    scannerId: string;
    displayName: string;
    score: number;
    weight: number;
    weightedContribution: number;
    riskLevel: RiskLevel;
    signals: Array<{
      signalId: string;
      description: string;
      severity: Severity;
      evidence: string;
    }>;
    executionMs: number;
    error?: string;
  }>;
  topSignals: Array<{
    signalId: string;
    description: string;
    severity: Severity;
    scannerId: string;
  }>;
  partialAnalysis: boolean;
  metadata: {
    totalExecutionMs: number;
    scannersRun: number;
    backendVersion: string;
    timestamp: string;
  };
}

export interface TestCase {
  id: string;
  description: string;
  category: "phishing" | "bec" | "benign";
  email: AnalyzeRequest;
  expect: {
    scoreMin: number;
    scoreMax: number;
  };
}

export interface TestResult {
  id: string;
  category: string;
  score: number;
  riskLevel: RiskLevel;
  expected: { scoreMin: number; scoreMax: number };
  passed: boolean;
  error?: string;
  executionMs: number;
}
