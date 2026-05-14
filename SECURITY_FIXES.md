# Security Fixes — Upwind Email Security Scorer

## Audit Summary

Full-stack security audit covering secrets handling, data encryption in transit, untrusted input handling, and prompt hijacking resistance.

---

## Findings & Fixes

### 1. Prompt Hijacking (HIGH) — Fixed

**File:** `backend/utils/claude.ts`

**Problem:** Email subject, sender domain, and body were inserted directly into the Claude prompt using XML-like tags with no escaping. An attacker could craft an email containing `</email_subject>` or `</email_content>` to break out of the tag boundary and inject arbitrary natural-language instructions into the LLM — for example, forcing a SAFE verdict on a malicious email.

**Fix applied:**
- Added `xmlEscape()` helper (encodes `&`, `<`, `>`) applied to subject, senderDomain, and body before embedding in the prompt.
- Moved all analyst instructions, scoring guide, and signal IDs into the `system` parameter of the Claude API call. Only the escaped email data is in the `user` message. This uses Claude's trust hierarchy (system prompt > user turn), making injected instructions in the user turn harder to act on.

**Primary defense:** `validateBECAnalysis()` validates and clamps the LLM output regardless of what the model returns. Structural output validation is the strongest prompt-injection defense because it does not rely on the model behaving correctly.

---

### 2. HSTS (MEDIUM) — Fixed

**File:** `backend/vercel.json`

**Problem:** No `Strict-Transport-Security` header was set. Without HSTS, clients have no instruction to enforce HTTPS-only connections.

**Fix applied:** Added `Strict-Transport-Security: max-age=31536000; includeSubDomains` to all API routes.

**Note on scope:** HSTS is primarily a browser-client protection. The main client here is Google Apps Script (server-to-server), where Vercel already enforces HTTPS at the infrastructure level. The header is defense-in-depth — it is correct to add but the practical risk without it was low.

---

### 3. Inconsistent HTML Size Limit (LOW) — Fixed

**File:** `addon/MimeParser.gs`

**Problem:** `getHtmlBody()` returned up to 200 KB (line 143), but `extractEmailPayload()` immediately truncated that to 20 KB (line 30). The 200 KB return cap was dead code — it caused unnecessary base64 decoding of up to 200 KB only to discard 99% of it.

**Fix applied:** Changed the `getHtmlBody()` return cap from 204,800 bytes to 20,480 bytes, consistent with the canonical limit in `extractEmailPayload()`.

---

### 4. Log Injection via Client-Supplied Request ID (LOW) — Fixed

**File:** `backend/api/analyze.ts`

**Problem:** The `requestId` was taken from the client-supplied `x-request-id` header without validation (`req.headers["x-request-id"] || crypto.randomUUID()`). A malicious caller could inject newlines or control characters into the request ID, producing forged log lines.

**Fix applied:** `requestId` is now always generated server-side with `crypto.randomUUID()`. The client-supplied header is ignored.

---

### 5. CTE Scope Bug in HTML MIME Parser (LOW) — Fixed

**File:** `addon/MimeParser.gs`

**Problem:** `getHtmlBody()` detected Content-Transfer-Encoding by searching the entire raw MIME message with a global regex. This picked up the *first* CTE in the message, which could belong to the plain-text part. If the plain-text part was base64-encoded but the HTML part was not, the HTML body would be incorrectly base64-decoded, producing garbled content or an exception.

**Fix applied:** The CTE search is now scoped to the HTML part's own header block (the slice of rawContent from the HTML part start to the next blank line).

---

## What Was Already Correct

| Area | Detail |
|------|--------|
| Secrets in add-on | PropertiesService (Google encrypted store) — no hardcoded secrets |
| Secrets in backend | Loaded from `process.env`, never hardcoded; `.env.local` gitignored |
| Auth token comparison | `crypto.timingSafeEqual()` — timing-attack safe (`analyze.ts:42`) |
| Rate limiting | In-memory per-token hash, 60 req/hr (`analyze.ts:14–27`) |
| Input size limits | 500 KB overall, 50 KB plain text, 20 KB HTML, 64 KB headers (`sanitizer.ts:3–6`) |
| CRLF injection prevention | Header values stripped of `\r\n` in sanitizer (`sanitizer.ts:28`) |
| Output escaping | `escapeHtml()` applied to all scanner evidence in API response (`analyze.ts:134`) |
| OAuth scopes | Minimal: `gmail.readonly`, `addons.execute`, `script.external_request` |
| Attachment content | Never transmitted — metadata only (`MimeParser.gs:33–46`) |
| LLM output validation | `validateBECAnalysis()` clamps scores and sanitizes all fields (`claude.ts:86–111`) |

## Known Limitations

| Limitation | Risk | Notes |
|---|---|---|
| Rate limiting resets on cold start | Low | In-memory map; Vercel cold starts reset the window. Acceptable at current scale. Migrate to Redis for production. |
| `timingSafeEqual` not constant-time for wrong-length tokens | Very low | Throws on length mismatch (caught); different-length tokens are rejected correctly but not via constant-time path. |
