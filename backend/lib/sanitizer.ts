import { AnalyzeRequest, AttachmentMeta, EmailContext, ParsedHeaders, ReceivedHop } from "./types";

const MAX_BODY_BYTES = 500 * 1024;
const MAX_PLAIN_BYTES = 50 * 1024;
const MAX_HTML_BYTES = 200 * 1024;
const MAX_HEADERS_BYTES = 64 * 1024;

// ─── Header map ───────────────────────────────────────────────────────────────

function buildHeaderMap(rawHeaders: string): ParsedHeaders {
  const map = new Map<string, string[]>();

  for (const line of rawHeaders.split(/\r?\n/)) {
    // Folded header continuation lines start with whitespace
    if (/^\s/.test(line)) {
      // Append to last header value
      const last = [...map.keys()].at(-1);
      if (last) {
        const vals = map.get(last)!;
        vals[vals.length - 1] += " " + line.trim();
      }
      continue;
    }
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const name = line.slice(0, colon).toLowerCase().trim();
    // Strip \r\n to prevent response splitting
    const value = line.slice(colon + 1).trim().replace(/[\r\n]/g, " ");
    const existing = map.get(name);
    if (existing) {
      existing.push(value);
    } else {
      map.set(name, [value]);
    }
  }

  return {
    get: (name: string) => map.get(name.toLowerCase())?.[0] ?? null,
    getAll: (name: string) => map.get(name.toLowerCase()) ?? [],
    has: (name: string) => map.has(name.toLowerCase()),
  };
}

// ─── Received chain parser ────────────────────────────────────────────────────

function parseReceivedChain(headers: ParsedHeaders): ReceivedHop[] {
  const lines = headers.getAll("received");
  return lines
    .map((line): ReceivedHop => {
      const fromMatch = line.match(/from\s+([^\s(]+)/i);
      const byMatch = line.match(/by\s+([^\s(]+)/i);
      const withMatch = line.match(/with\s+([^\s;(]+)/i);
      const dateStr = line.match(/;\s*(.+)$/)?.[1]?.trim() ?? null;
      return {
        from: fromMatch?.[1] ?? null,
        by: byMatch?.[1] ?? null,
        withProtocol: withMatch?.[1] ?? null,
        timestamp: dateStr ? new Date(dateStr) : null,
        rawLine: line,
      };
    })
    .reverse(); // bottom-up: originating server first
}

// ─── Domain extraction ────────────────────────────────────────────────────────

function extractDomain(email: string): string {
  const at = email.lastIndexOf("@");
  return at !== -1 ? email.slice(at + 1).toLowerCase().trim() : "";
}

// ─── Text extraction from HTML ────────────────────────────────────────────────

function extractTextFromHtml(html: string): string {
  // Strip tags, decode basic entities — keep it simple and safe
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s{2,}/g, " ")
    .trim();
}

// ─── Size guard ───────────────────────────────────────────────────────────────

function truncate(s: string | null, maxBytes: number): string | null {
  if (!s) return null;
  if (Buffer.byteLength(s, "utf8") <= maxBytes) return s;
  return s.slice(0, maxBytes);
}

// ─── Main sanitizer ───────────────────────────────────────────────────────────

export function sanitize(req: AnalyzeRequest): EmailContext {
  const safeHeaders = truncate(req.rawHeaders, MAX_HEADERS_BYTES) ?? "";
  const safePlain = truncate(req.body.plainText, MAX_PLAIN_BYTES);
  const safeHtml = truncate(req.body.htmlContent, MAX_HTML_BYTES);

  const totalBodyBytes =
    Buffer.byteLength(safePlain ?? "", "utf8") +
    Buffer.byteLength(safeHtml ?? "", "utf8");

  if (totalBodyBytes > MAX_BODY_BYTES) {
    throw new Error("REQUEST_TOO_LARGE");
  }

  const headers = buildHeaderMap(safeHeaders);
  const receivedChain = parseReceivedChain(headers);
  const domain = extractDomain(req.sender.emailAddress);
  const replyToDomain = req.sender.replyTo ? extractDomain(req.sender.replyTo) : null;

  const extractedText = safeHtml
    ? extractTextFromHtml(safeHtml)
    : (safePlain ?? "");

  const safeAttachments: AttachmentMeta[] = req.attachments.map((a) => ({
    filename: a.filename.replace(/[\r\n]/g, ""),
    mimeType: a.mimeType.replace(/[\r\n]/g, ""),
    sizeBytes: typeof a.sizeBytes === "number" ? a.sizeBytes : 0,
    sha256Hint: a.sha256Hint,
  }));

  return {
    messageId: req.envelope.messageId,
    headers,
    sender: {
      displayName: req.sender.displayName.replace(/[\r\n]/g, ""),
      emailAddress: req.sender.emailAddress.toLowerCase().trim(),
      domain,
      replyTo: req.sender.replyTo,
      replyToDomain,
    },
    subject: req.subject.replace(/[\r\n]/g, ""),
    body: {
      plainText: safePlain,
      htmlContent: safeHtml,
      extractedText,
    },
    attachments: safeAttachments,
    receivedChain,
    rawHeaders: safeHeaders,
  };
}
