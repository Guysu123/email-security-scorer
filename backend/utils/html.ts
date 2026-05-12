// HTML smuggling detection patterns
// These are the canonical primitives used to reconstruct payloads in browser memory

const SMUGGLING_PATTERNS: { pattern: RegExp; signalId: string; description: string }[] = [
  {
    pattern: /URL\.createObjectURL\s*\(/i,
    signalId: "HTML_SMUGGLING_CREATE_OBJECT_URL",
    description: "createObjectURL() call — used to trigger programmatic file downloads from in-memory blobs",
  },
  {
    pattern: /new\s+Blob\s*\(\s*\[/i,
    signalId: "HTML_SMUGGLING_BLOB_CONSTRUCTOR",
    description: "Blob constructor with array argument — typical payload reassembly pattern",
  },
  {
    pattern: /atob\s*\(/i,
    signalId: "HTML_SMUGGLING_BASE64_DECODE",
    description: "atob() Base64 decode in HTML body — used to reconstruct encoded payloads client-side",
  },
  {
    pattern: /String\.fromCharCode\s*\(/i,
    signalId: "HTML_SMUGGLING_CHARCODE",
    description: "String.fromCharCode() — obfuscates binary payload reconstruction",
  },
  {
    pattern: /<script[^>]*>/i,
    signalId: "HTML_SCRIPT_TAG",
    description: "Script tag present in email HTML — should never appear in legitimate email",
  },
];

export interface SmugglingScanResult {
  found: boolean;
  matches: Array<{ signalId: string; description: string }>;
}

export function detectHtmlSmuggling(html: string): SmugglingScanResult {
  const matches: Array<{ signalId: string; description: string }> = [];

  for (const { pattern, signalId, description } of SMUGGLING_PATTERNS) {
    if (pattern.test(html)) {
      matches.push({ signalId, description });
    }
  }

  // Extra: large inline data URIs (>512KB) as Base64 — classic payload embedding
  const dataUriMatches = html.matchAll(/data:[^;]+;base64,([A-Za-z0-9+/=]{50000,})/gi);
  for (const m of dataUriMatches) {
    matches.push({
      signalId: "HTML_LARGE_INLINE_PAYLOAD",
      description: `Oversized inline Base64 data URI (${Math.round(m[1].length * 0.75 / 1024)}KB) — potential embedded payload`,
    });
  }

  return { found: matches.length > 0, matches };
}

// Escape HTML entities in evidence strings before they appear in API responses
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Extract all URLs (http/https) from text content
export function extractUrls(text: string): string[] {
  const matches = text.matchAll(/https?:\/\/[^\s"'<>)\]]+/gi);
  return [...new Set([...matches].map((m) => m[0]))];
}
