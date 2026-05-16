// ─── Severity & Risk ─────────────────────────────────────────────────────────

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

// ─── Signal ───────────────────────────────────────────────────────────────────

export interface Signal {
  signalId: string;
  description: string;
  severity: Severity;
  evidence: string;
  metadata?: Record<string, unknown>;
}

// ─── Scanner Result ───────────────────────────────────────────────────────────

export interface ScannerResult {
  scannerId: string;
  displayName: string;
  score: number;
  riskLevel: RiskLevel;
  signals: Signal[];
  executionMs: number;
  error?: string;
}

// ─── Email Context (sanitized — what scanners receive) ────────────────────────

export interface ParsedHeaders {
  get(name: string): string | null;
  getAll(name: string): string[];
  has(name: string): boolean;
}

export interface ReceivedHop {
  from: string | null;
  by: string | null;
  withProtocol: string | null;
  timestamp: Date | null;
  rawLine: string;
}

export interface AttachmentMeta {
  filename: string;
  mimeType: string;
  sizeBytes: number;
  sha256Hint: string | null;
}

export interface EmailContext {
  messageId: string;
  headers: ParsedHeaders;
  sender: {
    displayName: string;
    emailAddress: string;
    domain: string;
    replyTo: string | null;
    replyToDomain: string | null;
  };
  subject: string;
  body: {
    plainText: string | null;
    htmlContent: string | null;
    extractedText: string;
  };
  attachments: AttachmentMeta[];
  receivedChain: ReceivedHop[];
  rawHeaders: string;
}

// ─── Scanner Interface ────────────────────────────────────────────────────────

export interface IScanner {
  readonly id: string;
  readonly displayName: string;
  readonly weight: number;
  readonly timeoutMs: number;
  scan(context: EmailContext): Promise<ScannerResult>;
}

// ─── API Request / Response ───────────────────────────────────────────────────

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

export interface ScannerResultPublic {
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
}

export interface AnalyzeResponse {
  requestId: string;
  analysisId: string;
  finalScore: number;
  riskLevel: RiskLevel;
  verdict: string;
  recommendation: string;
  scannerResults: ScannerResultPublic[];
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

export interface ErrorResponse {
  error: string;
  message: string;
  requestId: string;
}
