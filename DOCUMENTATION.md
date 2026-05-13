# Email Security Scorer — Technical Documentation

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [API Reference](#api-reference)
4. [Scoring Engine](#scoring-engine)
5. [Scanner Reference](#scanner-reference)
6. [Data Models](#data-models)
7. [Security Model](#security-model)
8. [Deployment](#deployment)

---

## System Overview

The Email Security Scorer is a two-component system:

| Component | Technology | Role |
|---|---|---|
| **Backend** | TypeScript on Vercel Serverless | Analysis engine, API surface |
| **Add-on** | Google Apps Script (CardService) | Gmail UI, email extraction, HTTP client |

The system operates on two threat planes simultaneously:

- **Structural/Technical** — headers, MIME, URLs, HTML patterns, authentication records
- **Semantic/Linguistic** — BEC social engineering patterns, urgency/authority language, AI-detected diction

---

## Architecture

### Request Lifecycle

```
User opens email in Gmail
        │
        ▼
onGmailMessage() [Code.gs]
  GmailApp.getMessageById(messageId)
        │
        ▼
extractEmailPayload() [MimeParser.gs]
  - Raw MIME split → headers block + body
  - getPlainBody() + getHtmlBody() (base64-decoded if needed)
  - Attachment blobs → metadata only (name, mimeType, sizeBytes)
  - parseDisplayName() + parseEmailAddress() from From header
        │
        ▼
callAnalyzeApi() [ApiClient.gs]
  POST /api/analyze
  Authorization: Bearer <ADDON_API_SECRET>
  Content-Type: application/json
        │
        ▼
handler() [api/analyze.ts]
  1. Method check (POST only)
  2. verifyAuth() — crypto.timingSafeEqual Bearer token comparison
  3. isRateLimited() — 60 req/hr per token hash (in-memory, resets on cold start)
  4. Body size guard — 500 KB hard limit before parsing
  5. validateRequest() — structural shape check (required fields present)
        │
        ▼
sanitize() [lib/sanitizer.ts]  ← Trust Boundary
  AnalyzeRequest (untrusted) → EmailContext (safe, typed)
  - Header truncation (64 KB max)
  - Folded-header RFC 5322 parsing → ParsedHeaders map
  - Received chain parsing → ReceivedHop[] (reversed: origin-first)
  - Domain extraction from emailAddress and replyTo
  - HTML → plaintext extraction (style/script stripped, entities decoded)
  - \r\n stripped from displayName, subject, attachment filenames
  - Total body size guard (500 KB combined)
        │
        ▼
runAnalysis() [lib/orchestrator.ts]
  Promise.allSettled([
    HeaderAuthScanner.scan(),      // weight 0.30, timeout 4 s
    BECLinguisticScanner.scan(),   // weight 0.25, timeout 12 s
    URLScanner.scan(),             // weight 0.20, timeout 5 s
    SenderReputationScanner.scan(),// weight 0.15, timeout 4 s
    ContentStructureScanner.scan(),// weight 0.10, timeout 4 s
  ])
  Each scanner wraps execute() in:
    - Individual per-scanner timeout (Promise.race)
    - try/catch returning a scored 0 / error result on failure
  → ScannerResult[] (always 5 results — never throws)
        │
        ▼
aggregate() [lib/scoring.ts]
  1. Weighted base score
  2. Critical signal override (floor → 70)
  3. Corroboration amplification (×1.2 if ≥3 scanners > 50)
  4. Weak corroboration floor (≥2 scanners with HIGH/CRITICAL → floor 40)
  5. Authentication attenuation (×0.8 if HeaderAuth < 10 AND BEC < 20)
  6. Top signals ranked by severity → verdict template selected
        │
        ▼
JSON response → buildResultCard() [CardBuilder.gs]
  Gmail sidebar card rendered from finalScore, riskLevel, verdict,
  per-scanner breakdown, topSignals
```

---

## API Reference

### `POST /api/analyze`

Analyzes a structured email payload and returns a scored threat assessment.

**Authentication:** `Authorization: Bearer <ADDON_API_SECRET>`

**Rate limit:** 60 requests per hour per token

**Request body** (`application/json`, max 500 KB):

```json
{
  "envelope": {
    "messageId": "string",
    "gmailThreadId": "string",
    "receivedTimestamp": "ISO 8601 string"
  },
  "rawHeaders": "string (max 64 KB)",
  "sender": {
    "displayName": "string",
    "emailAddress": "string",
    "replyTo": "string | null"
  },
  "subject": "string",
  "body": {
    "plainText": "string | null (max 50 KB)",
    "htmlContent": "string | null (max 200 KB)"
  },
  "attachments": [
    {
      "filename": "string",
      "mimeType": "string",
      "sizeBytes": "number",
      "sha256Hint": "string | null"
    }
  ],
  "requestMetadata": {
    "addonVersion": "string",
    "requestId": "UUID string",
    "timestamp": "ISO 8601 string"
  }
}
```

**Success response** `200 OK`:

```json
{
  "requestId": "uuid",
  "analysisId": "uuid",
  "finalScore": 0,
  "riskLevel": "LOW | MEDIUM | HIGH | CRITICAL",
  "verdict": "Human-readable threat summary string",
  "scannerResults": [
    {
      "scannerId": "string",
      "displayName": "string",
      "score": 0,
      "weight": 0.30,
      "weightedContribution": 0.0,
      "riskLevel": "LOW | MEDIUM | HIGH | CRITICAL",
      "signals": [
        {
          "signalId": "SCREAMING_SNAKE_CASE",
          "description": "string",
          "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
          "evidence": "HTML-entity-escaped string"
        }
      ],
      "executionMs": 0,
      "error": "string | undefined"
    }
  ],
  "topSignals": [
    {
      "signalId": "string",
      "description": "string",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "scannerId": "string"
    }
  ],
  "partialAnalysis": false,
  "metadata": {
    "totalExecutionMs": 0,
    "scannersRun": 5,
    "backendVersion": "1.0.0",
    "timestamp": "ISO 8601 string"
  }
}
```

**Error responses:**

| HTTP Status | `error` field | Cause |
|---|---|---|
| `400` | `VALIDATION_ERROR` | Required fields missing from request body |
| `401` | `UNAUTHORIZED` | Missing or invalid Bearer token |
| `405` | `METHOD_NOT_ALLOWED` | Non-POST request |
| `413` | `PAYLOAD_TOO_LARGE` | Request body or email content exceeds size limits |
| `429` | `RATE_LIMITED` | 60 requests/hour limit exceeded |
| `500` | `INTERNAL_ERROR` | Unexpected analysis failure |

All error responses include `requestId` for correlation:

```json
{
  "error": "RATE_LIMITED",
  "message": "Too many requests — max 60/hour",
  "requestId": "uuid"
}
```

---

### `GET /api/health`

Health check endpoint. No authentication required.

**Response** `200 OK`:

```json
{
  "status": "ok",
  "version": "1.0.0",
  "timestamp": "ISO 8601 string"
}
```

---

## Scoring Engine

### Base Score: Weighted Average

```
baseScore = Σ(scanner.score × scanner.weight) / Σ(scanner.weight)
```

Only scanners without errors (or with partial scores > 0) contribute to the denominator, preventing failed scanners from artificially suppressing the score.

### Scanner Weights

| Scanner | Weight | Rationale |
|---|---|---|
| HeaderAuthScanner | 30% | Authentication headers are the most objective, tamper-evident signals |
| BECLinguisticScanner | 25% | BEC is the highest-cost threat category; semantic analysis is unique value |
| URLScanner | 20% | Phishing links are the most common attack delivery mechanism |
| SenderReputationScanner | 15% | Strong corroborating signal but high false-positive rate standalone |
| ContentStructureScanner | 10% | Useful for malware delivery; rare in purely social-engineering BEC |

### Post-Processing Rules

Applied in order after the weighted average:

**1. Critical Signal Override**
Any signal with `severity === "CRITICAL"` lifts the floor to 70. Rationale: CRITICAL signals (DMARC_FAIL, HOMOGRAPH_ATTACK, HTML_SMUGGLING) represent near-certainties that should never produce a LOW verdict.

**2. Corroboration Amplification**
If ≥3 scanners independently score > 50, apply ×1.2 boost (capped at 100). Rationale: Multi-scanner agreement is strong evidence even when individual scores are moderate.

**3. Weak Corroboration Floor**
If ≥2 scanners produce HIGH or CRITICAL signals, floor raised to 40 (MEDIUM). Rationale: Two independent subsystems flagging serious issues should never produce a LOW verdict.

**4. Authentication Attenuation**
If `HeaderAuthScanner.score < 10` AND `BECLinguisticScanner.score < 20`, apply ×0.8 reduction. Rationale: Strong authentication + clean language is the strongest false-positive indicator — this targets legitimate marketing and automated emails that trip weak signals in other scanners.

### Risk Level Thresholds

```
CRITICAL: score ≥ 70
HIGH:     score 55–69
MEDIUM:   score 35–54
LOW:      score  0–34
```

### Verdict Generation

Verdicts are selected from a static template table keyed on `(riskLevel, topSignalIds)`. They are never LLM-generated. This is a deliberate security decision: adversarial email content cannot manipulate the verdict string through prompt injection.

---

## Scanner Reference

### HeaderAuthScanner (weight: 0.30)

Parses `Authentication-Results`, `DKIM-Signature`, and `Received` headers.

| Signal ID | Severity | Score Floor | Trigger |
|---|---|---|---|
| `DMARC_FAIL` | CRITICAL | 85 | dmarc=fail in Auth-Results |
| `DMARC_SOFTFAIL` | HIGH | 50 | dmarc=softfail |
| `DMARC_MISSING` | MEDIUM | 30 | No Authentication-Results header |
| `DMARC_POLICY_NONE` | MEDIUM | 35 | p=none (monitoring only) |
| `DKIM_FAIL` | HIGH | 55 | dkim=fail |
| `DKIM_DOMAIN_MISMATCH` | HIGH | 55 | DKIM d= ≠ From domain |
| `SPF_FAIL` | HIGH | 40 | spf=fail |
| `SPF_SOFTFAIL` | MEDIUM | 30 | spf=softfail |
| `RECEIVED_CHAIN_EMPTY` | MEDIUM | 20 | Zero Received headers |
| `RECEIVED_TIMESTAMP_INVERSION` | MEDIUM | 35 | Out-of-order hop timestamps |
| `SMTP_SMUGGLING_INDICATOR` | CRITICAL | 90 | Bare LF end-of-data sequence |
| `REPLY_TO_FOREIGN_TLD` | LOW | 30 | Reply-To TLD ≠ From TLD (non-generic) |

### BECLinguisticScanner (weight: 0.25)

Two-stage analysis: rule-based regex patterns (Stage 1) followed by Claude Haiku LLM analysis gated on Stage 1 score > 25 (Stage 2).

**Stage 1 Signal IDs:**

| Signal ID | Severity | Score Floor | Trigger |
|---|---|---|---|
| `URGENCY_LANGUAGE_HIGH` | HIGH | 60 | ≥3 urgency pattern matches |
| `URGENCY_LANGUAGE_LOW` | LOW | 25 | 1–2 urgency patterns |
| `AUTHORITY_IMPERSONATION` | HIGH | 55 | ≥2 authority patterns |
| `FINANCIAL_REQUEST_LANGUAGE` | HIGH | 50 | ≥2 financial patterns |
| `FINANCIAL_MENTION` | LOW | 20 | 1 financial pattern |
| `CREDENTIAL_REQUEST` | HIGH | 55 | ≥1 credential pattern |
| `BEC_TRIFECTA` | CRITICAL | 80 | urgency + authority + financial all present |
| `FEATURE_STARVATION_BEC` | MEDIUM | 40 | < 30 words with financial intent |

**Stage 2 (LLM):** Claude Haiku is prompted with plain text only (max 3,000 chars), subject, and sender domain. Returns a `becScore` (0–100) and additional signals. The LLM contribution is blended at 40% weight against Stage 1 score. All LLM output is schema-validated; invalid responses are silently dropped with an `LLM_UNAVAILABLE` signal added.

### URLScanner (weight: 0.20)

| Signal ID | Severity | Score Floor | Trigger |
|---|---|---|---|
| `HOMOGRAPH_ATTACK` | CRITICAL | 95 | Punycode domain matches known brand |
| `SUBDOMAIN_CONFUSION` | CRITICAL | 85 | Brand name appears as non-authoritative subdomain |
| `TYPOSQUATTING_DETECTED` | HIGH | 70 | Edit distance ≤2 from known brand domain |
| `URL_SHORTENER` | MEDIUM | 30 | Known shortener domain (bit.ly, tinyurl, etc.) |
| `OPEN_REDIRECT_CHAIN` | HIGH | 85 | Security vendor redirector wraps a typosquat |
| `EXCESSIVE_URL_COUNT` | MEDIUM | 25 | > 20 unique URLs in message |
| `HTML_SMUGGLING_*` | CRITICAL | 90 | JS payload-reconstruction primitives detected |

### SenderReputationScanner (weight: 0.15)

| Signal ID | Severity | Score Floor | Trigger |
|---|---|---|---|
| `DISPLAY_NAME_SPOOFING` | HIGH | 65 | Display name contains brand name; From domain doesn't match |
| `SUBDOMAIN_CONFUSION_SENDER` | HIGH | 80 | Sender domain embeds brand as subdomain |
| `LOOKALIKE_DOMAIN` | HIGH | 70 | Sender domain typosquats a known brand |
| `REPLY_TO_MISMATCH` | HIGH/MEDIUM | 65/40 | Reply-To domain ≠ From domain (HIGH if free provider) |
| `FREE_PROVIDER_FINANCIAL_REQUEST` | HIGH | 50 | Free email provider + financial content |
| `FREE_PROVIDER_SENDER` | INFO | 10 | Free email provider (no other flags) |
| `SELF_SENT_EMAIL` | MEDIUM | 35 | From address appears in To header |

### ContentStructureScanner (weight: 0.10)

| Signal ID | Severity | Score Floor | Trigger |
|---|---|---|---|
| `DANGEROUS_ATTACHMENT` | CRITICAL | 90 | Executable extension (.exe, .ps1, .vbs, etc.) |
| `HIGH_RISK_MIME_TYPE` | CRITICAL | 85 | application/x-msdownload etc. |
| `DOUBLE_EXTENSION_ATTACK` | CRITICAL | 90 | file.pdf.exe double extension |
| `CONTAINER_ATTACHMENT` | MEDIUM | 30 | .zip/.iso/.img archive |
| `OVERSIZED_DOCUMENT` | MEDIUM | 25 | Document > 10 MB |
| `HTML_ONLY_NO_PLAINTEXT` | LOW | 15 | HTML body, missing or empty text/plain |
| `MIME_DEEP_NESTING` | MEDIUM | 30 | > 5 nested multipart sections |
| `HIDDEN_CONTENT_CSS` | LOW | 20 | font-size:0 or display:none in HTML |
| `MISSING_MESSAGE_ID` | LOW | 20 | Message-ID header absent |

---

## Data Models

### `EmailContext` (internal, scanners receive this)

```typescript
interface EmailContext {
  messageId: string;
  headers: ParsedHeaders;          // case-insensitive, folded-header-aware
  sender: {
    displayName: string;
    emailAddress: string;          // lowercased
    domain: string;                // extracted from emailAddress
    replyTo: string | null;
    replyToDomain: string | null;
  };
  subject: string;
  body: {
    plainText: string | null;      // max 50 KB
    htmlContent: string | null;    // max 200 KB
    extractedText: string;         // HTML → text stripped version
  };
  attachments: AttachmentMeta[];   // metadata only, no content bytes
  receivedChain: ReceivedHop[];    // reversed: index 0 = originating server
  rawHeaders: string;              // max 64 KB
}
```

### `ScannerResult` (internal, orchestrator collects these)

```typescript
interface ScannerResult {
  scannerId: string;
  displayName: string;
  score: number;          // 0–100, integer
  riskLevel: RiskLevel;
  signals: Signal[];
  executionMs: number;
  error?: string;         // present on timeout or exception
}
```

---

## Security Model

### Trust Boundary

`sanitizer.ts` is the sole trust boundary. The raw `AnalyzeRequest` — which contains attacker-controlled content — is never passed directly to scanners. All scanners receive the sanitized `EmailContext`.

### Defense-in-Depth Layers

| Layer | Mechanism |
|---|---|
| Authentication | `crypto.timingSafeEqual` Bearer token comparison |
| Rate limiting | 60 req/hr per SHA-256 token hash (token never logged) |
| Input validation | Structural shape check before parsing |
| Size guards | 500 KB total request; 64 KB headers; 50 KB plain; 200 KB HTML |
| Header sanitization | `\r\n` stripped from all string fields (injection prevention) |
| XSS in evidence | All `Signal.evidence` HTML-entity-escaped before serialization |
| LLM prompt injection | Plain text only; XML delimiters; schema validation; 40% weight cap |
| Secret handling | Vercel env vars + Apps Script ScriptProperties; hashed for rate-limit keys |
| Scope minimization | Add-on requests `gmail.readonly` and `gmail.addons.execute` only |
| SSRF | `openLinkUrlPrefixes` in appsscript.json restricts UrlFetchApp to backend domain |

### Prompt Injection Mitigation (BECLinguisticScanner)

The LLM receives:
- Plain text only (HTML stripped by sanitizer — no HTML rendering primitives)
- Content wrapped in `<email_content>...</email_content>` XML delimiters
- A strict JSON-only response schema
- Maximum 3,000 character truncation of body content

The LLM output is validated against a strict schema; any non-conforming response is silently dropped. The LLM contributes at most 40% blend weight — a fully compromised LLM response cannot drive the final score below the Stage 1 baseline.

---

## Deployment

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `ADDON_API_SECRET` | Yes | Shared secret between add-on and backend. Min 32 random bytes, base64 encoded. |
| `ANTHROPIC_API_KEY` | No | Enables Stage 2 LLM analysis in BECLinguisticScanner. Analysis runs without it (Stage 1 only). |

### Apps Script Properties

| Property | Value |
|---|---|
| `BACKEND_URL` | Vercel deployment URL (e.g. `https://email-security-scorer.vercel.app`) |
| `ADDON_API_SECRET` | Same value as Vercel `ADDON_API_SECRET` env var |

### Adding a New Scanner

1. Create `backend/scanners/YourScanner.ts` extending `BaseScanner`
2. Implement `execute(context: EmailContext): Promise<ScannerResult>` using `this.buildResult(score, signals)`
3. Add to `SCANNERS` array in `backend/lib/orchestrator.ts`

No other changes required. The orchestrator, scoring engine, and API response format handle new scanners automatically.

```typescript
import { BaseScanner } from "./base";
import { EmailContext, ScannerResult } from "../lib/types";

export class IPReputationScanner extends BaseScanner {
  readonly id = "IPReputationScanner";
  readonly displayName = "IP Reputation";
  readonly weight = 0.10;
  readonly timeoutMs = 3000;

  protected async execute(context: EmailContext): Promise<ScannerResult> {
    const signals = [];
    let score = 0;
    // ... detection logic using context.receivedChain[0] etc. ...
    return this.buildResult(score, signals);
  }
}
```
