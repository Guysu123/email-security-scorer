# Email Security Scorer — Technical Documentation

## Table of Contents

1. [System Overview](#system-overview)
2. [Architecture](#architecture)
3. [Add-on Components](#add-on-components)
4. [API Reference](#api-reference)
5. [Scoring Engine](#scoring-engine)
6. [Scanner Reference](#scanner-reference)
7. [Data Models](#data-models)
8. [Security Model](#security-model)
9. [Known Limitations](#known-limitations)
10. [Configuration Reference](#configuration-reference)
11. [Test Suite](#test-suite)
12. [Extending the System](#extending-the-system)

---

## System Overview

The Email Security Scorer is a two-component system:

| Component | Technology | Role |
|---|---|---|
| **Backend** | TypeScript on Vercel Serverless | Analysis engine, API surface |
| **Add-on** | Google Apps Script (CardService) | Gmail UI, email extraction, HTTP client, user data storage |

The system analyzes emails on two threat planes simultaneously:

- **Structural / Technical** — SMTP authentication (SPF, DKIM, DMARC), header chain anomalies, URL homograph and typosquat attacks, HTML smuggling primitives, attachment deception patterns
- **Semantic / Linguistic** — BEC urgency / authority / financial language patterns, AI-assisted BEC intent detection via Claude Haiku

---

## Architecture

### Full Request Lifecycle

```
User opens email in Gmail
        │
        ▼
onGmailMessage() [Code.gs]
  └── GmailApp.getMessageById(messageId)
        │
        ▼
getCachedResult(messageId) [Cache.gs]
  ├── HIT  → buildResultCard(cached) — returns immediately, no network call
  └── MISS → continues to extraction
        │
        ▼
extractEmailPayload() [MimeParser.gs]
  ├── Raw MIME split → headers block + body
  ├── getPlainBodyFromRaw() — decodes base64 CTE if present
  ├── getHtmlBody() — finds text/html part in MIME tree
  ├── Attachment blobs → metadata only (name, mimeType, sizeBytes)
  └── parseDisplayName() + parseEmailAddress() from From header
        │
        ▼
callAnalyzeApi() [ApiClient.gs]
  ├── Optional: encryptPayload() [Crypto.gs] — HMAC-SHA256-CTR
  └── POST /api/analyze
      Authorization: Bearer <ADDON_API_SECRET>
      Content-Type: application/json
        │
        ▼
handler() [api/analyze.ts]
  1. Method check (POST only)
  2. verifyAuth() — crypto.timingSafeEqual Bearer token comparison
  3. isRateLimited() — 60 req/hr per token hash (in-memory, resets on cold start)
  4. Body size guard — 500 KB hard limit before parsing
  5. Optional: decryptPayload() — if body contains "enc" field
  6. validateRequest() — structural shape check (required fields present)
        │
        ▼
sanitize() [lib/sanitizer.ts]  ◄── Trust Boundary
  AnalyzeRequest (untrusted) → EmailContext (safe, typed)
  ├── Header truncation (64 KB max)
  ├── Folded-header RFC 5322 parsing → ParsedHeaders map
  ├── Received chain parsing → ReceivedHop[] (reversed: origin-first)
  ├── Domain extraction from emailAddress and replyTo
  ├── HTML → plaintext extraction (style/script stripped, entities decoded)
  ├── \r\n stripped from displayName, subject, attachment filenames
  └── Total body size guard (500 KB combined)
        │
        ▼
runAnalysis() [lib/orchestrator.ts]
  Promise.allSettled([
    HeaderAuthScanner.scan(),       // weight 0.30, timeout 4 s
    BECLinguisticScanner.scan(),    // weight 0.25, timeout 12 s
    URLScanner.scan(),              // weight 0.20, timeout 5 s
    SenderReputationScanner.scan(), // weight 0.15, timeout 4 s
    ContentStructureScanner.scan(), // weight 0.10, timeout 4 s
  ])
  Each scanner: individual timeout (Promise.race) + try/catch
  → Always returns 5 ScannerResult objects, never throws
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
AnalyzeResponse (JSON) returned to ApiClient.gs
        │
        ▼
setCachedResult(messageId, result.data) [Cache.gs]
  └── Stores compacted result for 30 min (PropertiesService, ≤9 KB)
        │
        ▼
appendScoreHistory() [Storage.gs]
  └── Persists {id, ts, score, risk, subject, sender} to PropertiesService
        │
        ▼
buildResultCard() [CardBuilder.gs]
  └── Gmail sidebar card: score, risk level, verdict, "What To Do" recommendation,
      signals, scanner breakdown, Re-analyze / My Stats / Dispute score / Open Stats Dashboard buttons
```

---

## Add-on Components

The Gmail add-on (`addon/`) is a Google Apps Script project deployed via [clasp](https://github.com/google/clasp). It contains the following modules:

### Code.gs — Entry Points and Handlers

All global functions that Apps Script can invoke as triggers or card actions.

| Function | Type | Description |
|---|---|---|
| `onGmailMessage(e)` | Contextual trigger | Fires when an email is opened. Checks cache first; on miss, extracts payload, calls backend, writes cache, saves history, renders result card. |
| `onRetry(e)` | Card action | Evicts the cache entry for the current message, then re-runs `onGmailMessage` to force a fresh backend call. |
| `onHomepage(e)` | Homepage trigger | Fired when the add-on panel is open but no email is selected. Returns the stats card. |
| `onShowStats(e)` | Card action | Pushes the stats card onto the navigation stack. |
| `onShowFeedbackForm(e)` | Card action | Pushes the feedback form card. Receives `messageId`, `score`, `riskLevel` as parameters. |
| `onSubmitFeedback(e)` | Card action | Reads form inputs, calls `appendFeedback()`, pops card, shows toast. |
| `onCancelFeedback(e)` | Card action | Pops the feedback form card without saving. |
| `authCallback()` | Authorization check | Always returns `true`; required by the manifest. |

### CardBuilder.gs — UI Construction

Builds all Gmail sidebar cards using the CardService API. CardService has no CSS — layout is achieved through widget composition.

| Function | Returns | Description |
|---|---|---|
| `buildLoadingCard()` | `Card` | Shown immediately while the API call is in flight. |
| `buildErrorCard(msg)` | `Card` | Displayed on API errors with a Retry button. |
| `buildResultCard(data)` | `Card` | Main results card: risk badge, score, verdict, "What To Do" recommendation, key findings, collapsible scanner breakdown, action buttons. |
| `buildFeedbackFormCard(messageId, score, riskLevel)` | `Card` | Form with radio buttons for suggested risk level and a multiline comment field. |
| `buildStatsCard()` | `Card` | In-sidebar stats view: overview metrics, breakdown by risk level, collapsible recent history. Calls `computeStats()`. |

### MimeParser.gs — Email Payload Extraction

Extracts structured data from the raw `GmailMessage` object without additional API calls.

- Splits raw MIME on `\r\n\r\n` (or `\n\n` as fallback) to separate headers from body
- Handles `Content-Transfer-Encoding: base64` for both plain-text and HTML parts
- Extracts attachment metadata only — content bytes are never read
- Truncates defensively: headers 64 KB, plain text 51 KB, HTML 20 KB

### ApiClient.gs — Backend HTTP Client

Sends the structured payload to `POST /api/analyze` using `UrlFetchApp`.

- Timeout: 25 seconds (Vercel function maxDuration is 30 s)
- If `PAYLOAD_ENCRYPTION_KEY` is set, wraps payload in `{"enc": "<ciphertext>"}` via `Crypto.gs`
- Uses `muteHttpExceptions: true` for structured error handling
- Returns `{ ok, data, statusCode, error }`

### Cache.gs — Per-Request Result Cache

Caches analysis results in `PropertiesService.getUserProperties()` to avoid redundant backend calls when the same email is reopened within the cache window.

- **Key:** `bec_<messageId>`
- **TTL:** 30 minutes — expiry checked on read; stale entries deleted lazily
- **Size limit:** 9 KB per property — `compactForCache()` strips non-essential fields before writing
- Compaction keeps: `finalScore`, `riskLevel`, `verdict`, `recommendation`, top 3 signals per scorer scanner (descriptions truncated to 100 chars)
- **Cache invalidation:** `onRetry` explicitly deletes the property before re-running analysis, ensuring "Re-analyze" always fetches fresh results

### Storage.gs — User History and Feedback

Persists per-user score history and feedback in `PropertiesService.getUserProperties()`. Data is scoped to the Google account that authorized the add-on and never leaves Google's infrastructure.

**Score History** — key: `SCORE_HISTORY_V1`

```json
[
  {
    "id":    "analysisId-uuid",
    "ts":    1747000000000,
    "score": 75,
    "risk":  "HIGH",
    "subj":  "Urgent: wire transfer needed",
    "from":  "ceo@evil.com"
  }
]
```

- Max 100 entries; newest first; deduplicated by `id`
- Subject truncated to 50 chars, sender to 40 chars
- Size guard: trims oldest entries if serialized JSON exceeds 9 KB

**Feedback Log** — key: `FEEDBACK_LOG_V1`

```json
[
  {
    "id":            "analysisId-uuid",
    "ts":            1747000000000,
    "score":         75,
    "risk":          "HIGH",
    "suggestedRisk": "LOW",
    "comment":       "This is from my colleague"
  }
]
```

- Max 50 entries; newest first; deduplicated by `id`
- Comment truncated to 500 chars

| Function | Description |
|---|---|
| `getScoreHistory()` | Returns array; `[]` on parse error |
| `appendScoreHistory(entry)` | Deduplicates, prepends, trims to 100 |
| `getFeedbackHistory()` | Returns array; `[]` on parse error |
| `appendFeedback(entry)` | Deduplicates, prepends, trims to 50 |
| `computeStats()` | Returns `{ total, avgScore, mostCommonRisk, byRisk, recent }` |

### WebApp.gs — Stats Dashboard Server

Serves the `Stats.html` page when the Apps Script project is deployed as a web app.

| Function | Description |
|---|---|
| `doGet(e)` | Serves `Stats.html` via `HtmlService.createHtmlOutputFromFile()` |
| `getStatsData()` | Called from `Stats.html` via `google.script.run`. Returns `{ stats, history, feedback }`. Runs server-side so it can access `PropertiesService`. |

### Stats.html — Full-Page Dashboard

A self-contained HTML page with inline CSS and JavaScript. Loaded via `google.script.run.getStatsData()` — no external CDN dependencies.

Sections:
1. **KPI cards** — total analyzed, average threat score, critical+high count, feedbacks given
2. **Risk distribution** — horizontal bar chart per risk level (CSS-based, no canvas)
3. **Email history table** — all analyzed emails with date, sender, subject, score, risk badge
4. **Score feedback table** — all disputes with original score, your suggested risk, and comment

### Crypto.gs — Optional Payload Encryption

Implements authenticated HMAC-SHA256-CTR encryption for the request payload. Disabled by default; enabled by setting `PAYLOAD_ENCRYPTION_KEY` on both sides.

**Wire format:** `base64(nonce[16] || ciphertext[n] || mac[32])`

- Stream cipher: HMAC-SHA256 in CTR mode (keystream = HMAC(key, nonce || counter))
- Authentication tag: HMAC-SHA256 over `nonce || ciphertext`
- Compatible with the Node.js `decryptPayload()` in `backend/lib/encryption.ts`

### Constants.gs — Runtime Configuration

All values loaded from Script Properties (encrypted by Google at rest).

| Function | Script Property | Default |
|---|---|---|
| `getBackendUrl()` | `BACKEND_URL` | `https://upwind-email-scorer.vercel.app` |
| `getApiSecret()` | `ADDON_API_SECRET` | `""` |
| `getEncryptionKey()` | `PAYLOAD_ENCRYPTION_KEY` | `null` |
| `getWebAppUrl()` | `STATS_WEBAPP_URL` | `null` |

`ADDON_VERSION` is hard-coded as `"1.0.1"` and sent to the backend in the `X-Addon-Version` request header.

---

## API Reference

### `POST /api/analyze`

Analyzes a structured email payload and returns a scored threat assessment.

**Authentication:** `Authorization: Bearer <ADDON_API_SECRET>`

**Rate limit:** 60 requests per hour per token (keyed on `SHA-256(token).slice(0,16)`)

**Request body** (`application/json`, max 500 KB):

```json
{
  "envelope": {
    "messageId":          "string  — RFC 5322 Message-ID or Gmail internal ID",
    "gmailThreadId":      "string",
    "receivedTimestamp":  "ISO 8601 string"
  },
  "rawHeaders":  "string  (max 64 KB)",
  "sender": {
    "displayName":  "string",
    "emailAddress": "string",
    "replyTo":      "string | null"
  },
  "subject": "string",
  "body": {
    "plainText":   "string | null  (max 50 KB)",
    "htmlContent": "string | null  (max 200 KB)"
  },
  "attachments": [
    {
      "filename":   "string",
      "mimeType":   "string",
      "sizeBytes":  "number",
      "sha256Hint": "string | null"
    }
  ],
  "requestMetadata": {
    "addonVersion": "string",
    "requestId":    "UUID string",
    "timestamp":    "ISO 8601 string"
  }
}
```

**Encrypted request body** (when `PAYLOAD_ENCRYPTION_KEY` is configured):

```json
{
  "enc": "<base64-encoded nonce+ciphertext+mac>"
}
```

The backend detects the `enc` field and decrypts before validation.

**Success response** `200 OK`:

```json
{
  "requestId":   "uuid",
  "analysisId":  "uuid",
  "finalScore":       75,
  "riskLevel":        "HIGH",
  "verdict":          "Strong urgency and pressure language detected alongside sender anomalies.",
  "recommendation":   "Do not follow any instructions without first verifying the sender's identity through a separate channel. Do not click links or open attachments.",
  "scannerResults": [
    {
      "scannerId":            "HeaderAuthScanner",
      "displayName":          "Header Authentication",
      "score":                85,
      "weight":               0.30,
      "weightedContribution": 25.5,
      "riskLevel":            "CRITICAL",
      "signals": [
        {
          "signalId":    "DMARC_FAIL",
          "description": "DMARC policy check failed — sender domain disavows this message",
          "severity":    "CRITICAL",
          "evidence":    "dmarc=fail (p=reject)"
        }
      ],
      "executionMs": 312,
      "error": null
    }
  ],
  "topSignals": [
    {
      "signalId":    "DMARC_FAIL",
      "description": "DMARC policy check failed — sender domain disavows this message",
      "severity":    "CRITICAL",
      "scannerId":   "HeaderAuthScanner"
    }
  ],
  "partialAnalysis": false,
  "metadata": {
    "totalExecutionMs": 1843,
    "scannersRun":      5,
    "backendVersion":   "1.0.0",
    "timestamp":        "2026-05-15T10:00:00.000Z"
  }
}
```

**Notes on the response:**

- `scannerResults` always contains exactly 5 entries, one per scanner, in the order: HeaderAuth → BECLinguistic → URL → SenderReputation → ContentStructure
- If a scanner times out or throws, its `score` is `0`, `signals` is `[]`, and `error` is set. `partialAnalysis` is `true` in this case.
- `topSignals` contains the top 5 signals across all scanners, ranked by severity
- `verdict` and `recommendation` are static template strings selected server-side — they are never LLM-generated, which prevents prompt injection from influencing what the user is told to do
- All `evidence` strings are HTML-entity-escaped

**Error responses:**

| HTTP | `error` field | Cause |
|---|---|---|
| `400` | `VALIDATION_ERROR` | Required fields missing from request body |
| `400` | `DECRYPTION_FAILED` | `enc` field present but decryption failed (wrong key or tampered payload) |
| `401` | `UNAUTHORIZED` | Missing or invalid Bearer token |
| `405` | `METHOD_NOT_ALLOWED` | Non-POST request |
| `413` | `PAYLOAD_TOO_LARGE` | Request body or email content exceeds size limits |
| `429` | `RATE_LIMITED` | 60 requests/hour limit exceeded |
| `500` | `INTERNAL_ERROR` | Unexpected analysis failure |

All error responses share this shape:

```json
{
  "error":     "RATE_LIMITED",
  "message":   "Too many requests — max 60/hour",
  "requestId": "uuid"
}
```

---

### `GET /api/health`

Health check. No authentication required.

**Response** `200 OK`:

```json
{
  "status":    "ok",
  "version":   "1.0.0",
  "timestamp": "2026-05-15T10:00:00.000Z",
  "scanners": [
    "HeaderAuthScanner",
    "BECLinguisticScanner",
    "URLScanner",
    "SenderReputationScanner",
    "ContentStructureScanner"
  ]
}
```

---

## Scoring Engine

### Step 1 — Weighted Base Score

```
baseScore = Σ(scanner.score × scanner.weight)
```

Failed scanners (score = 0, error set) contribute 0 to the numerator. Their weight is still counted in the denominator, which means a scanner failure slightly suppresses the total — a safe-fail in the direction of under-detection rather than over-detection.

### Step 2 — Post-Processing Rules

Applied in sequence after the weighted average:

#### Rule 1: Critical Signal Override

```
if any signal.severity == "CRITICAL":
    baseScore = max(baseScore, 70)
```

CRITICAL signals (e.g., `DMARC_FAIL`, `HOMOGRAPH_ATTACK`, `HTML_SMUGGLING_DETECTED`) represent near-certainties. A single CRITICAL finding should never produce a LOW or MEDIUM verdict.

#### Rule 2: Corroboration Amplification

```
if count(scanners where score > 50) >= 3:
    baseScore = min(100, baseScore × 1.2)
```

When three or more independent scanners independently agree the email is threatening, their agreement is treated as stronger evidence than the weighted average alone captures.

#### Rule 3: Weak Corroboration Floor

```
if count(scanners with any HIGH or CRITICAL signal) >= 2:
    baseScore = max(baseScore, 40)
```

Two independent subsystems each flagging a serious issue should never produce a LOW verdict, even if the weighted average is low due to other scanners scoring 0.

#### Rule 4: Authentication Attenuation

```
if HeaderAuthScanner.score < 10 AND BECLinguisticScanner.score < 20:
    baseScore = baseScore × 0.8
```

Strong email authentication (near-zero header score) combined with clean language (near-zero BEC score) is the strongest false-positive indicator. This targets legitimate marketing and automated notification emails that incidentally trip weak signals in URL or content scanners.

### Step 3 — Finalize

```
finalScore = clamp(round(baseScore), 0, 100)
riskLevel  = scoreToRiskLevel(finalScore)
```

| Risk Level | Score Range |
|---|---|
| `CRITICAL` | 70 – 100 |
| `HIGH` | 55 – 69 |
| `MEDIUM` | 35 – 54 |
| `LOW` | 0 – 34 |

### Verdict and Recommendation Selection

Verdicts and recommendations are selected from static template tables keyed on `(riskLevel, topSignalIds)`. They are **never LLM-generated**. This is a deliberate security decision: adversarial email content cannot manipulate what the user is told to do through prompt injection.

#### Recommendations

Recommendations are keyed solely on `riskLevel` — one template per level, always shown:

| Risk Level | Recommendation |
|---|---|
| `CRITICAL` | Do not click any links, open attachments, or reply. Verify the request by calling the sender on a known phone number — not one in this email. Report as phishing. |
| `HIGH` | Do not follow any instructions without first verifying the sender's identity through a separate channel (phone call, in-person). Do not click links or open attachments. |
| `MEDIUM` | Proceed with caution. Confirm the sender's identity before sharing information or taking financial action. When in doubt, contact through official channels. |
| `LOW` | No action required. Standard email hygiene applies. |

#### Verdicts

| Risk Level | Signal Key | Verdict |
|---|---|---|
| CRITICAL | `DMARC_FAIL` + `WIRE_TRANSFER` | "Authentication completely fails and urgent financial language detected — consistent with CEO fraud." |
| CRITICAL | `DMARC_FAIL` | "Email authentication completely fails — this message cannot be verified as coming from the claimed sender." |
| CRITICAL | `HOMOGRAPH_ATTACK` | "Domain uses look-alike Unicode characters designed to visually impersonate a trusted brand." |
| CRITICAL | `BEC_AUTHORITY` | "Combines authority impersonation with urgency to pressure immediate action — hallmark of Business Email Compromise." |
| HIGH | `DKIM_FAIL` | "Email signature verification failed — message may have been tampered with in transit." |
| HIGH | `URGENCY_LANGUAGE` | "Strong urgency and pressure language detected alongside sender anomalies." |
| HIGH | `LOOKALIKE_DOMAIN` | "Sender domain is a near-identical misspelling of a trusted brand — likely spoofing attack." |
| MEDIUM | `REPLY_TO_MISMATCH` | "Reply-To address differs from the sender — responses will go to a different party than expected." |
| MEDIUM | `FREE_PROVIDER` | "Unusual combination of free email provider with financial or credential request." |
| Any | `DEFAULT` | Risk-level default template |

### Scanner Weights — Rationale

| Scanner | Weight | Rationale |
|---|---|---|
| HeaderAuthScanner | 30% | Authentication headers are the most objective, tamper-evident signals — forging DMARC pass is cryptographically hard |
| BECLinguisticScanner | 25% | BEC is the highest-cost threat category ($2.9B/yr); semantic analysis is the unique value of this system |
| URLScanner | 20% | Phishing links are the most common attack delivery mechanism in commodity phishing |
| SenderReputationScanner | 15% | Strong corroborating signal but high standalone false-positive rate (many legitimate senders use free providers) |
| ContentStructureScanner | 10% | Primarily catches malware delivery; rarely relevant in purely social-engineering BEC |

---

## Scanner Reference

### HeaderAuthScanner (weight: 0.30, timeout: 4 s)

Parses `Authentication-Results`, `DKIM-Signature`, and `Received` headers from the raw header block.

| Signal ID | Severity | Score Floor | Trigger |
|---|---|---|---|
| `DMARC_FAIL` | CRITICAL | 85 | `dmarc=fail` in Authentication-Results |
| `DMARC_SOFTFAIL` | HIGH | 50 | `dmarc=softfail` |
| `DMARC_MISSING` | MEDIUM | 30 | No Authentication-Results header present |
| `DMARC_POLICY_NONE` | MEDIUM | 35 | DMARC policy `p=none` (monitoring only, not enforced) |
| `DKIM_FAIL` | HIGH | 55 | `dkim=fail` |
| `DKIM_DOMAIN_MISMATCH` | HIGH | 55 | DKIM `d=` signing domain differs from From domain |
| `SPF_FAIL` | HIGH | 40 | `spf=fail` |
| `SPF_SOFTFAIL` | MEDIUM | 30 | `spf=softfail` |
| `RECEIVED_CHAIN_EMPTY` | MEDIUM | 20 | Zero `Received` headers (suspicious for real mail) |
| `RECEIVED_TIMESTAMP_INVERSION` | MEDIUM | 35 | Out-of-order hop timestamps in Received chain |
| `SMTP_SMUGGLING_INDICATOR` | CRITICAL | 90 | Bare LF end-of-data sequence in raw headers |
| `REPLY_TO_FOREIGN_TLD` | LOW | 30 | Reply-To TLD differs from From TLD (excluding generic domains) |

---

### BECLinguisticScanner (weight: 0.25, timeout: 12 s)

Two-stage analysis. Stage 1 runs always. Stage 2 (Claude Haiku) only runs when the Stage 1 score exceeds 25 — this gates approximately 80% of emails out of the LLM path.

#### Stage 1 — Rule-Based Regex Patterns

| Signal ID | Severity | Score Floor | Trigger |
|---|---|---|---|
| `URGENCY_LANGUAGE_HIGH` | HIGH | 60 | ≥ 3 urgency pattern matches (e.g., "immediately", "urgent", "by end of day") |
| `URGENCY_LANGUAGE_LOW` | LOW | 25 | 1–2 urgency patterns |
| `AUTHORITY_IMPERSONATION` | HIGH | 55 | ≥ 2 authority patterns (e.g., "CEO", "CFO", "wire transfer from executive") |
| `FINANCIAL_REQUEST_LANGUAGE` | HIGH | 50 | ≥ 2 financial patterns (e.g., "wire transfer", "bank account", "routing number") |
| `FINANCIAL_MENTION` | LOW | 20 | 1 financial pattern |
| `CREDENTIAL_REQUEST` | HIGH | 55 | ≥ 1 credential pattern (e.g., "username and password", "login credentials") |
| `BEC_TRIFECTA` | CRITICAL | 80 | Urgency + authority + financial all present simultaneously |
| `FEATURE_STARVATION_BEC` | MEDIUM | 40 | Fewer than 30 words in body combined with financial intent |

#### Stage 2 — Claude Haiku LLM Analysis

**Inputs to the LLM:**
- Plain text only (HTML is stripped by the sanitizer — no HTML rendering exploits possible)
- Subject and sender domain included for context
- Maximum 3,000 characters of body content
- Content wrapped in `<email_content>...</email_content>` XML delimiters

**Output schema** (validated; non-conforming responses are dropped):
```typescript
{
  becScore: number,    // 0–100 LLM assessment
  signals: Array<{
    signalId:    string,
    description: string,
    evidence:    string,
    severity:    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  }>
}
```

**Score blending:** `finalStage2Score = (Stage1Score × 0.6) + (LLMScore × 0.4)`

The LLM contributes at most 40% of the blended score — it cannot single-handedly override the Stage 1 baseline. If the LLM is unavailable or returns invalid JSON, an `LLM_UNAVAILABLE` signal is added and Stage 1 score is used as-is.

---

### URLScanner (weight: 0.20, timeout: 5 s)

Extracts all URLs from both HTML and plain-text body, then checks each against a set of threat detectors.

| Signal ID | Severity | Score Floor | Trigger |
|---|---|---|---|
| `HOMOGRAPH_ATTACK` | CRITICAL | 95 | Punycode domain decodes to a look-alike of a known brand (e.g., `xn--gogle-ppa.com` → `gοgle.com`) |
| `SUBDOMAIN_CONFUSION` | CRITICAL | 85 | Brand name appears as a non-authoritative subdomain (e.g., `paypal.com.attacker.net`) |
| `TYPOSQUATTING_DETECTED` | HIGH | 70 | Levenshtein edit distance ≤ 2 from a known brand domain |
| `URL_SHORTENER` | MEDIUM | 30 | Known URL shortener domain (bit.ly, tinyurl.com, etc.) — destination unknown |
| `OPEN_REDIRECT_CHAIN` | HIGH | 85 | Security vendor redirector wraps a typosquatted domain |
| `EXCESSIVE_URL_COUNT` | MEDIUM | 25 | More than 20 unique URLs in the message |
| `HTML_SMUGGLING_DETECTED` | CRITICAL | 90 | JS payload-reconstruction primitives (`atob`, `Uint8Array`, `fromCharCode`, `createObjectURL`) |
| `HTML_SMUGGLING_BLOB` | CRITICAL | 90 | `Blob` constructor with `application/octet-stream` in HTML |

---

### SenderReputationScanner (weight: 0.15, timeout: 5 s)

Analyzes the relationship between the display name, From address, Reply-To address, and known legitimate domains.

| Signal ID | Severity | Score Floor | Trigger |
|---|---|---|---|
| `DISPLAY_NAME_SPOOFING` | HIGH | 65 | Display name contains a brand name but From domain does not match that brand |
| `SUBDOMAIN_CONFUSION_SENDER` | HIGH | 80 | Sender domain embeds a brand name as a subdomain |
| `LOOKALIKE_DOMAIN` | HIGH | 70 | Sender domain is within Levenshtein distance ≤ 2 of a known brand domain |
| `REPLY_TO_MISMATCH` | HIGH | 65 | Reply-To domain differs from From domain **and** Reply-To is a free provider |
| `REPLY_TO_MISMATCH` | MEDIUM | 40 | Reply-To domain differs from From domain (corporate-to-corporate mismatch) |
| `FREE_PROVIDER_FINANCIAL_REQUEST` | HIGH | 50 | Free email provider (gmail.com, yahoo.com, etc.) combined with financial content |
| `FREE_PROVIDER_SENDER` | INFO | 10 | Free email provider with no other flags |
| `SELF_SENT_EMAIL` | MEDIUM | 35 | From address appears in the To header (spoofed self-send) |

---

### ContentStructureScanner (weight: 0.10, timeout: 5 s)

Analyzes MIME structure, attachment metadata, and HTML content for structural threat indicators.

| Signal ID | Severity | Score Floor | Trigger |
|---|---|---|---|
| `DANGEROUS_ATTACHMENT` | CRITICAL | 90 | Executable extension: `.exe`, `.ps1`, `.vbs`, `.bat`, `.cmd`, `.scr`, `.msi`, `.hta` |
| `HIGH_RISK_MIME_TYPE` | CRITICAL | 85 | `application/x-msdownload`, `application/x-executable`, etc. |
| `DOUBLE_EXTENSION_ATTACK` | CRITICAL | 90 | File with double extension (e.g., `invoice.pdf.exe`) |
| `CONTAINER_ATTACHMENT` | MEDIUM | 30 | Archive format: `.zip`, `.rar`, `.iso`, `.img`, `.7z` — may conceal executable contents |
| `OVERSIZED_DOCUMENT` | MEDIUM | 25 | Document attachment exceeds 10 MB |
| `HTML_ONLY_NO_PLAINTEXT` | LOW | 15 | HTML body with missing or empty `text/plain` part |
| `MIME_DEEP_NESTING` | MEDIUM | 30 | More than 5 nested `multipart/*` sections |
| `HIDDEN_CONTENT_CSS` | LOW | 20 | `font-size:0`, `color:white`, or `display:none` in HTML |
| `MISSING_MESSAGE_ID` | LOW | 20 | `Message-ID` header absent |

---

## Data Models

### `AnalyzeRequest` — Add-on → Backend

The raw untrusted payload sent by the add-on. All fields from this type pass through the `sanitizer.ts` trust boundary before reaching any scanner.

```typescript
interface AnalyzeRequest {
  envelope: {
    messageId:          string;
    gmailThreadId:      string;
    receivedTimestamp:  string;
  };
  rawHeaders:   string;
  sender: {
    displayName:  string;
    emailAddress: string;
    replyTo:      string | null;
  };
  subject:     string;
  body: {
    plainText:   string | null;
    htmlContent: string | null;
  };
  attachments: Array<{
    filename:   string;
    mimeType:   string;
    sizeBytes:  number;
    sha256Hint: string | null;
  }>;
  requestMetadata: {
    addonVersion: string;
    requestId:    string;
    timestamp:    string;
  };
}
```

### `EmailContext` — Internal (scanners receive this)

The sanitized, trusted representation of an email. Produced by `sanitizer.ts` from an `AnalyzeRequest`. Scanners only ever see `EmailContext` — never the raw request.

```typescript
interface EmailContext {
  messageId:  string;
  headers:    ParsedHeaders;       // case-insensitive, folded-header-aware Map
  sender: {
    displayName:    string;
    emailAddress:   string;        // lowercased
    domain:         string;        // extracted from emailAddress
    replyTo:        string | null;
    replyToDomain:  string | null;
  };
  subject: string;
  body: {
    plainText:     string | null;  // max 50 KB
    htmlContent:   string | null;  // max 200 KB
    extractedText: string;         // HTML stripped to plain text
  };
  attachments:   AttachmentMeta[];
  receivedChain: ReceivedHop[];    // index 0 = originating server
  rawHeaders:    string;           // max 64 KB
}
```

### `ScannerResult` — Internal (orchestrator collects these)

```typescript
interface ScannerResult {
  scannerId:   string;
  displayName: string;
  score:       number;      // 0–100, integer
  riskLevel:   RiskLevel;
  signals:     Signal[];
  executionMs: number;
  error?:      string;      // set on timeout or uncaught exception
}

interface Signal {
  signalId:    string;       // SCREAMING_SNAKE_CASE
  description: string;
  severity:    Severity;     // CRITICAL | HIGH | MEDIUM | LOW | INFO
  evidence:    string;       // raw excerpt — HTML-escaped before API serialization
  metadata?:   Record<string, unknown>;
}
```

---

## Security Model

### Trust Boundary

`sanitizer.ts` is the sole trust boundary between attacker-controlled data and the analysis engine. The raw `AnalyzeRequest` is never passed to scanners. All sanitization happens once, at a well-defined interface.

```
AnalyzeRequest (untrusted, attacker-controlled)
        │
        ▼
   sanitizer.ts  ◄── TRUST BOUNDARY
        │
        ▼
EmailContext (safe, typed, size-bounded)
        │
     scanners
```

### Defense-in-Depth Layers

| Layer | Mechanism |
|---|---|
| **Transport** | HTTPS only; Vercel handles TLS termination |
| **Optional encryption** | HMAC-SHA256-CTR payload encryption on top of TLS |
| **Authentication** | `crypto.timingSafeEqual` Bearer token comparison — constant-time, prevents timing oracle |
| **Rate limiting** | 60 req/hr keyed on `SHA-256(token).slice(0,16)` — raw token never logged |
| **Request size** | 500 KB hard limit enforced before JSON parsing |
| **Input validation** | Structural shape check before sanitization |
| **Size guards** | Per-field limits: 64 KB headers, 50 KB plain text, 200 KB HTML |
| **Header injection** | `\r\n` stripped from all string fields in sanitizer |
| **XSS in evidence** | All `Signal.evidence` values HTML-entity-escaped before serialization |
| **LLM prompt injection** | Plain text only; XML delimiters; schema validation; 40% contribution weight cap |
| **Secret handling** | Vercel env vars (backend) + Apps Script ScriptProperties (add-on); token hashed for log keys |
| **Scope minimization** | Add-on requests `gmail.readonly` and `gmail.addons.execute` only — no write access |
| **URL fetch allowlist** | `urlFetchWhitelist` in `appsscript.json` restricts `UrlFetchApp` to the backend domain |

### Prompt Injection Mitigation (BECLinguisticScanner)

The BEC scanner is the only component that passes email content to an LLM. Mitigations applied:

1. **Plain text only** — HTML stripped by the sanitizer before reaching the scanner. No HTML rendering primitives can reach the LLM.
2. **XML delimiters** — Email content is wrapped in `<email_content>...</email_content>` to structurally separate attacker content from instructions.
3. **Character limit** — Maximum 3,000 characters of body content, truncated before the LLM call.
4. **JSON schema validation** — LLM output is validated against a strict schema. Any non-conforming response (including injection attempts that corrupt the output format) is silently dropped.
5. **Weight cap** — LLM contributes at most 40% blend weight. A fully compromised LLM response cannot drive the final score below the Stage 1 rule-based baseline.
6. **Judge evaluation** — The `test/llm-judge` suite uses Claude Sonnet to grade Haiku's responses for accuracy, evidence quality, and false-positive risk on labeled samples.

---

## Known Limitations

### Cryptographic

**Nonce generation in `Crypto.gs`** — The HMAC-SHA256-CTR encryption uses `Math.random()` to generate the 16-byte per-message nonce because Apps Script does not expose a native CSPRNG. `Math.random()` is a deterministic PRNG seeded by the V8 runtime and is not cryptographically secure. Nonce reuse under the same key in CTR mode allows an attacker who observes two ciphertexts to recover the XOR of their plaintexts. The practical risk for a personal single-user deployment is low (the attacker must also defeat TLS), but this is a known weakness. A production implementation would use `Utilities.computeHmacSha256Signature` seeded with a timestamp and a per-session script property to produce unpredictable nonces within the Apps Script sandbox.

### Detection Gaps

**No attachment content scanning** — only filename, MIME type, and size are inspected. Executing or parsing attachment content requires an isolated detonation sandbox with no outbound network access (e.g., AWS Lambda with a VPC endpoint).

**No image analysis / OCR** — content embedded in images is invisible to all scanners. This includes QR code phishing, where the attacker encodes a malicious URL as a QR image to bypass URL-based detection entirely. This is one of the most active current attack vectors.

**No domain age signal** — newly registered domains (< 30 days old) appear in the majority of targeted phishing campaigns. A WHOIS/RDAP lookup on the sender domain at analysis time would catch a large class of attacks that have no reputation data because the domain was registered specifically for this campaign.

**SMTP smuggling heuristic has limited reach** — `SMTP_SMUGGLING_INDICATOR` looks for a bare-LF DATA terminator (`\n.\n`) in the raw header block. Gmail's MTA strips the SMTP DATA protocol layer before delivering the message, so this pattern rarely fires in practice. The signal is retained as a structural placeholder; real SMTP smuggling detection requires inspection at the MTA boundary, before delivery.

### Architecture

**Expert-tuned scorer weights** — the 30/25/20/15/10 scanner weight distribution is based on domain knowledge, not a trained model. Weights have not been calibrated against a labeled phishing/legitimate corpus. A production system would derive and periodically retrain weights using logistic regression over historical scored data.

**In-memory rate limiting** — the rate limiter in `api/analyze.ts` uses a `Map` in the Vercel function's memory. This state is lost on every cold start. The limit is appropriate for single-user deployment; multi-tenant deployment requires a persistent counter store (Redis, Vercel KV, or similar).

**`sha256Hint` is always null** — `AttachmentMeta.sha256Hint` is defined in the data model and propagated through the full pipeline, but `MimeParser.gs` always sets it to `null`. The field was designed to support hash-based lookups against a threat intelligence feed; that integration was not implemented in this version.

### LLM

**Prompt injection is mitigated, not eliminated** — plain-text-only input, XML delimiters, strict JSON schema validation, and the 40% blend-weight cap significantly reduce the attack surface. A fine-tuned binary classifier trained on phishing/BEC examples would be more robust against adversarial inputs than a general-purpose instruction-following model.

---

## Configuration Reference

### Backend — Environment Variables

Set in `backend/.env.local` for local development. Set in the Vercel dashboard (**Settings → Environment Variables**) for production.

| Variable | Required | Description |
|---|---|---|
| `ADDON_API_SECRET` | ✅ Yes | Pre-shared secret authenticating the add-on. Must match the Apps Script `ADDON_API_SECRET` property. Generate: `openssl rand -hex 32` |
| `ANTHROPIC_API_KEY` | ✅ Yes | Enables Stage 2 LLM analysis in `BECLinguisticScanner`. Without it, analysis runs Stage 1 only. |
| `PAYLOAD_ENCRYPTION_KEY` | ⬜ Optional | 64-char hex key for HMAC-SHA256-CTR payload encryption. Must match Apps Script `PAYLOAD_ENCRYPTION_KEY`. Generate: `openssl rand -hex 32` |
| `LOG_LEVEL` | ⬜ Optional | `debug` \| `info` \| `warn` \| `error`. Default: `info` |

### Add-on — Script Properties

Set in **Apps Script editor → Project Settings → Script Properties**.

| Property | Required | Description |
|---|---|---|
| `BACKEND_URL` | ✅ Yes | Base URL of the backend. No trailing slash. Use Vercel URL for production; ngrok URL for local dev. |
| `ADDON_API_SECRET` | ✅ Yes | Exact same value as the backend `ADDON_API_SECRET` env var. |
| `PAYLOAD_ENCRYPTION_KEY` | ⬜ Optional | Exact same value as the backend `PAYLOAD_ENCRYPTION_KEY`. Leave unset on both sides to disable encryption. |
| `STATS_WEBAPP_URL` | ⬜ Optional | The `https://script.google.com/macros/s/.../exec` URL from the Apps Script web app deployment. Enables the "Open Stats Dashboard" button. |

---

## Test Suite

There are two independent layers of testing: unit tests for pure backend functions (no running server required), and integration tests for end-to-end scoring quality against a live API.

### Unit Tests (`backend/__tests__/`)

Run offline in milliseconds using [Vitest](https://vitest.dev/). Cover the pure-function core of the backend: typosquat detection, scoring aggregation rules, and HTML smuggling pattern matching.

```bash
cd backend
npm test
```

| File | Coverage |
|---|---|
| `punycode.test.ts` | `checkTyposquat` (digit substitutions, hyphen prefix, rn→m), `checkHomograph` (punycode label extraction), `checkSubdomainConfusion` |
| `scoring.test.ts` | `scoreToRiskLevel` boundary values, `aggregate` weighted average, CRITICAL signal floor override, corroboration boost (≥3 scanners), `topSignals` ordering |
| `html.test.ts` | `detectHtmlSmuggling` (all 5 primitives + large data URIs), `extractUrls` (deduplication), `escapeHtml` (XSS prevention) |

### Batch Runner (`test/batch/`)

Sends real email payloads to the live API and asserts that each result falls within the expected score range.

```bash
cd test && npm install

# Run against local Vercel dev server (default)
npx tsx batch/runner.ts

# Run against a specific backend
TEST_API_URL=https://your-project.vercel.app \
TEST_API_SECRET=your_secret \
npx tsx batch/runner.ts
```

Test cases are organized in three categories:

| Category | File | Expectation |
|---|---|---|
| `phishing` | `cases/phishing.ts` | High structural threat indicators (DMARC failures, homograph URLs) |
| `bec` | `cases/bec.ts` | No technical payload — tests semantic/linguistic detection only |
| `benign` | `cases/benign.ts` | Legitimate emails — guards against false positives |

Each test case defines:
```typescript
{
  id:          "PHISH_GOOGLE_DOCS_2017",
  description: "Typosquatted Google domain",
  category:    "phishing",
  email:       AnalyzeRequest,    // full realistic email payload
  expect: {
    scoreMin: 70,
    scoreMax: 100
  }
}
```

The runner prints a formatted pass/fail table and exits non-zero on any failure.

### LLM Judge (`test/llm-judge/`)

Uses Claude Sonnet as a judge to evaluate the quality of Haiku's BEC analysis on a set of labeled email samples.

```bash
ANTHROPIC_API_KEY=sk-ant-... npx tsx llm-judge/judge.ts
```

The judge scores Haiku's output on three dimensions (1–5 scale):

| Dimension | 5 (Best) | 1 (Worst) |
|---|---|---|
| `scoreAccuracy` | BEC score in expected range | Wrong risk tier |
| `evidenceQuality` | All evidence is specific quoted phrases from the email | Generic paraphrases |
| `falsePositiveRisk` | Benign emails correctly scored low | Benign email incorrectly flagged |

A final verdict of **GOOD** requires an average ≥ 3.5 across all dimensions. Below 3.5 prints **NEEDS IMPROVEMENT** with the reasoning.

---

## Extending the System

### Adding a New Scanner

1. Create `backend/scanners/YourScanner.ts` extending `BaseScanner`
2. Implement `protected async execute(context: EmailContext): Promise<ScannerResult>`
3. Add to the `SCANNERS` array in `backend/lib/orchestrator.ts`

No other changes are needed. The orchestrator, scoring engine, and API response format handle new scanners automatically.

```typescript
import { BaseScanner } from "./base";
import { EmailContext, ScannerResult } from "../lib/types";

export class IPReputationScanner extends BaseScanner {
  readonly id          = "IPReputationScanner";
  readonly displayName = "IP Reputation";
  readonly weight      = 0.10;
  readonly timeoutMs   = 3000;

  protected async execute(context: EmailContext): Promise<ScannerResult> {
    const signals = [];
    let score = 0;

    const firstHop = context.receivedChain[0];
    if (firstHop) {
      // ... check firstHop.ip against a reputation list ...
    }

    return this.buildResult(score, signals);
  }
}
```

**Important:** When adding a scanner, adjust the existing scanner weights so they still sum to 1.0.
