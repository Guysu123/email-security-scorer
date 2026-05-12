# Upwind Email Security Scorer

A Gmail Add-on that analyzes opened emails and produces a 0–100 maliciousness score with a per-signal explainable verdict.

---

## The Problem This Solves

Business Email Compromise (BEC) caused **$2.9 billion in reported losses in 2023**. The defining characteristic of BEC: **zero technical payload**. No malicious links. No dangerous attachments. No executable code. Just precisely calibrated social engineering language — and traditional signature-based filters are completely blind to it.

This system operates on two threat planes simultaneously:

- **Structural/Technical Plane** — headers, MIME structure, URLs, HTML patterns
- **Semantic/Linguistic Plane** — intent, social engineering patterns, urgency/authority pressure

Most commercial email security products only operate on the first plane. This architecture covers both.

---

## Architecture

```
Gmail (contextual trigger — fires when email is opened)
    │
    ↓ onGmailMessage()
Apps Script (Code.gs)
    → GmailApp.getMessageById() — raw MIME + headers
    → MimeParser.gs — structured payload extraction
    → UrlFetchApp POST /api/analyze
        │
        ↓
Vercel Serverless Function (api/analyze.ts)
    → sanitizer.ts — AnalyzeRequest → safe EmailContext (trust boundary)
    → orchestrator.ts — Promise.allSettled([...5 scanners in parallel...])
    → scoring.ts — weighted aggregation + amplification rules
    ← JSON: finalScore, riskLevel, verdict, per-scanner breakdown
        │
        ↓
CardBuilder.gs → Gmail Sidebar Card
```

Each scanner is **independently isolated** — a timeout or failure in one scanner does not block the analysis. The response always includes whatever results are available, with a `partialAnalysis` flag.

---

## The Five Scanners

| Scanner | Weight | What it detects |
|---|---|---|
| **HeaderAuthScanner** | 30% | SPF/DKIM/DMARC failures, Received chain anomalies, SMTP Smuggling indicators |
| **BECLinguisticScanner** | 25% | Urgency language, authority impersonation, feature starvation, AI-diction (Stage 2: Claude API) |
| **URLScanner** | 20% | Punycode/homograph attacks, typosquatting, HTML Smuggling primitives, subdomain confusion |
| **SenderReputationScanner** | 15% | Lookalike domains, Reply-To mismatch, display name spoofing, free provider + financial combos |
| **ContentStructureScanner** | 10% | Dangerous attachments, double extensions, MIME anomalies, hidden CSS content |

### Scoring Algorithm

```
baseScore = Σ (scanner.score × scanner.weight)

# Critical signal override: any CRITICAL finding lifts floor to 70
if any signal.severity == CRITICAL: finalScore = max(baseScore, 70)

# Corroboration amplification: ≥3 scanners agree → boost confidence
if ≥3 scanners score > 50: finalScore = min(100, baseScore × 1.2)

# Authentication attenuation: strong DMARC pass reduces false positives
if HeaderAuth.score < 10 AND BECLinguistic.score < 20: finalScore = baseScore × 0.8

Risk levels: CRITICAL ≥70 | HIGH 55–69 | MEDIUM 35–54 | LOW 0–34
```

Verdicts are **template-generated server-side** — never LLM-generated. This prevents adversarial email content from manipulating the verdict text through prompt injection.

---

## Architecture Decision Records

### ADR-1: Serverless Functions over Express Server

**Decision:** Each backend route is a standalone Vercel serverless function (`api/*.ts`), not a long-running Express server.

**Rationale:** Forced statelessness eliminates an entire class of attacks — there is no persistent process holding secrets in memory, no session state to hijack, no middleware chain where a misconfigured middleware could leak data between requests. Each invocation starts cold with only the environment variables it needs.

### ADR-2: Google Apps Script over Browser Extension

**Decision:** The add-on uses the native Google Workspace Add-on framework (Apps Script with CardService contextual triggers) rather than a Chrome extension injecting into the Gmail DOM.

**Rationale:** Contextual triggers provide access to the **full raw MIME message** via `GmailApp.getMessageById()`. A browser extension can only see the rendered HTML — which Gmail has already processed and partially sanitized. SMTP Smuggling indicators, raw `Received` header chains, and MIME structure anomalies are only visible in the raw message. The raw MIME is where the truth lives.

### ADR-3: LLM Analysis Gated Behind Rule-Based Stage 1

**Decision:** The `BECLinguisticScanner` invokes Claude only when the Stage 1 rule-based score exceeds 25.

**Rationale:**
1. **Cost control** — most emails score 0 at Stage 1. Gating eliminates ~80% of LLM API calls.
2. **Prompt injection surface reduction** — an adversary will craft BEC emails specifically to manipulate an LLM into returning low scores. By gating, we only expose the LLM to emails already flagged as suspicious, and we:
   - Send only sanitized plain text (never HTML)
   - Wrap content in XML delimiters
   - Schema-validate all LLM responses (any invalid response is discarded)
   - Cap the LLM's score contribution at 40% blend weight — it cannot single-handedly drive the final score to zero

---

## Threat Model

| Threat | Attack Vector | Mitigation | Residual Risk |
|---|---|---|---|
| **Prompt Injection** | Adversarial email content manipulates LLM into returning benign verdict | Plain text only; XML delimiters; schema validation; 40% cap on LLM contribution | LLM could still partially suppress score for sophisticated attacks |
| **Header Injection** | Raw email headers injected into UrlFetchApp HTTP request | All request data serialized via `JSON.stringify()` — never string-concatenated | Low — JSON serialization is safe |
| **Oversized Payload DoS** | Email with massive body to exhaust backend | 500KB request limit enforced before any parsing; per-field size caps in sanitizer | Very low |
| **API Key Exposure** | Secret leaked via logs or error responses | Keys stored in Vercel env vars + Apps Script ScriptProperties; never logged; timing-safe comparison; hash used for rate-limit keys | Low if deployment follows documented procedure |
| **Evidence XSS** | HTML in email body rendered as markup in sidebar | All `Signal.evidence` strings HTML-entity-escaped before serialization | CardService doesn't execute JS, but defense in depth is maintained |

---

## Adding a New Scanner

The modular scanner pattern means a new detection module is a single file drop. Here's the complete implementation of a hypothetical `IPReputationScanner`:

```typescript
// backend/scanners/IPReputationScanner.ts
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
    // ... detection logic ...
    return this.buildResult(score, signals);
  }
}
```

Then add it to `backend/lib/orchestrator.ts`:
```typescript
import { IPReputationScanner } from "../scanners/IPReputationScanner";
const SCANNERS: IScanner[] = [
  // ... existing scanners ...
  new IPReputationScanner(),
];
```

No other changes required. The orchestrator, scoring engine, and API response format all handle it automatically.

---

## Security Handling

- **Untrusted input isolation:** Raw `AnalyzeRequest` → `sanitizer.ts` → typed `EmailContext`. Scanners never receive the raw request object.
- **No PII in logs:** Structured logger never includes email addresses, body content, or subject lines.
- **Scope minimization:** Add-on requests only `gmail.readonly` and `gmail.addons.execute`. No write permissions.
- **Secret management:** `ADDON_API_SECRET` and `ANTHROPIC_API_KEY` stored in Vercel environment variables and Apps Script `ScriptProperties` respectively — never in source code.
- **SSRF prevention:** `openLinkUrlPrefixes` in `appsscript.json` is an allowlist that restricts `UrlFetchApp` calls to the backend domain only.

---

## Local Development

```bash
# 1. Install backend dependencies
cd backend && npm install

# 2. Create local environment file
cp .env.example .env.local
# Edit .env.local with your ADDON_API_SECRET and ANTHROPIC_API_KEY

# 3. Start backend dev server
npm run dev
# Listening on http://localhost:3000

# 4. Expose via ngrok
ngrok http 3000
# → https://abc123.ngrok.io

# 5. Configure Apps Script
# In Apps Script Editor → Project Settings → Script Properties:
#   BACKEND_URL      = https://abc123.ngrok.io
#   ADDON_API_SECRET = (same value as .env.local)

# 6. Deploy add-on
cd ../addon
npx @google/clasp push
npx @google/clasp deploy --description "dev"

# 7. Install in Gmail
# Follow the deployment URL → Install Add-on → Open any email
```

## Production Deployment

```bash
# Deploy backend to Vercel
cd backend
vercel deploy --prod
# Set environment variables in Vercel dashboard:
#   ADDON_API_SECRET, ANTHROPIC_API_KEY

# Update Apps Script BACKEND_URL to Vercel deployment URL
# Re-deploy add-on:
npx @google/clasp deploy --description "prod"

# Verify backend health
curl https://your-project.vercel.app/api/health
```

---

## Project Structure

```
upwind-email-scorer/
├── addon/                    # Google Apps Script (clasp-deployable)
│   ├── appsscript.json       # Manifest: scopes, trigger, OAuth
│   ├── Code.gs               # Contextual trigger entry point
│   ├── CardBuilder.gs        # Gmail sidebar UI
│   ├── ApiClient.gs          # Backend HTTP client
│   ├── MimeParser.gs         # Email data extraction
│   └── Constants.gs          # Runtime config + UI helpers
│
├── backend/
│   ├── api/
│   │   ├── analyze.ts        # POST /api/analyze
│   │   └── health.ts         # GET /api/health
│   ├── lib/
│   │   ├── types.ts          # All TypeScript interfaces
│   │   ├── sanitizer.ts      # Trust boundary (raw → safe EmailContext)
│   │   ├── orchestrator.ts   # Parallel scanner execution
│   │   ├── scoring.ts        # Weighted aggregation algorithm
│   │   └── logger.ts         # Structured logging (no PII)
│   ├── scanners/
│   │   ├── base.ts           # Abstract BaseScanner with timeout isolation
│   │   ├── HeaderAuthScanner.ts
│   │   ├── BECLinguisticScanner.ts
│   │   ├── URLScanner.ts
│   │   ├── SenderReputationScanner.ts
│   │   └── ContentStructureScanner.ts
│   └── utils/
│       ├── claude.ts         # Anthropic SDK wrapper (schema-validated)
│       ├── html.ts           # HTML smuggling detection + entity escaping
│       ├── punycode.ts       # Homograph/typosquat detection
│       └── dns.ts            # SPF/DMARC record fetching
│
├── .env.example
└── .gitignore
```

---

## Known Limitations & Future Work

**Current limitations** (intentional scope decisions, not oversights):

1. **No attachment content scanning** — sending attachment bytes to an external API raises data privacy concerns that are disproportionate to the value in a single-user deployment. A production system would use an isolated sandbox (e.g., AWS Lambda with no outbound network) for content detonation.

2. **Expert-tuned scorer weights** — the 30/25/20/15/10 weight distribution is based on domain knowledge, not a labeled dataset. A production system would derive weights via logistic regression on a balanced phishing/legitimate corpus (e.g., CEAS, SpamAssassin public datasets).

3. **DNS checks are best-effort** — serverless functions have no persistent cache, so DNS lookups happen on every invocation. High-volume deployment would add a Redis layer for TTL-based DNS response caching.

4. **LLM prompt injection is mitigated, not eliminated** — the schema validation and contribution cap reduce the attack surface significantly, but a sufficiently crafted adversarial prompt could still partially suppress the BEC score. A fine-tuned classification model on labeled BEC samples would be more robust than a general-purpose LLM.

5. **Rate limiting resets on cold start** — the in-memory rate limiter is sufficient for a single-user add-on but would need a persistent store (Redis, Vercel KV) for multi-tenant deployment.

---

*Built for the Upwind Security Bootcamp — demonstrating that the most dangerous attacks leave no technical fingerprints.*
