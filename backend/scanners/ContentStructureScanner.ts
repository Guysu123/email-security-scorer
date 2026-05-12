import { BaseScanner } from "./base";
import { EmailContext, ScannerResult, Signal } from "../lib/types";
import { detectHtmlSmuggling } from "../utils/html";
import { escapeHtml } from "../utils/html";

// Directly executable or dangerous attachment extensions
const HIGH_RISK_EXTENSIONS = new Set([
  ".exe", ".com", ".bat", ".cmd", ".scr", ".pif",
  ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
  ".ps1", ".ps2", ".msi", ".msp", ".hta", ".jar",
  ".dll", ".sys", ".reg",
]);

// Container formats commonly used to wrap high-risk content
const CONTAINER_EXTENSIONS = new Set([
  ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img", ".vhd", ".vhdx",
]);

// Double-extension detection: file.pdf.exe, document.docx.js
const DOUBLE_EXTENSION_RE = /\.[a-zA-Z]{2,5}\.[a-zA-Z]{2,4}$/;

// MIME types that should never appear in email attachments
const HIGH_RISK_MIME_TYPES = new Set([
  "application/x-msdownload",
  "application/x-executable",
  "application/x-sh",
  "application/x-msdos-program",
  "text/javascript",
  "application/javascript",
]);

function getExtension(filename: string): string {
  const lower = filename.toLowerCase();
  const lastDot = lower.lastIndexOf(".");
  return lastDot !== -1 ? lower.slice(lastDot) : "";
}

export class ContentStructureScanner extends BaseScanner {
  readonly id = "ContentStructureScanner";
  readonly displayName = "Content & Structure";
  readonly weight = 0.10;
  readonly timeoutMs = 4000;

  protected async execute(context: EmailContext): Promise<ScannerResult> {
    const signals: Signal[] = [];
    let score = 0;

    // ── Attachment analysis ───────────────────────────────────────────────────
    for (const attachment of context.attachments) {
      const ext = getExtension(attachment.filename);
      const safeFilename = escapeHtml(attachment.filename);

      // Direct high-risk extension
      if (HIGH_RISK_EXTENSIONS.has(ext)) {
        score = Math.max(score, 90);
        signals.push(
          this.signal(
            "DANGEROUS_ATTACHMENT",
            `Attachment has executable extension — direct execution risk`,
            "CRITICAL",
            `Filename: ${safeFilename} (${attachment.mimeType})`,
          )
        );
        continue;
      }

      // High-risk MIME type regardless of extension
      if (HIGH_RISK_MIME_TYPES.has(attachment.mimeType.toLowerCase())) {
        score = Math.max(score, 85);
        signals.push(
          this.signal(
            "HIGH_RISK_MIME_TYPE",
            `Attachment MIME type indicates executable content`,
            "CRITICAL",
            `Filename: ${safeFilename} | MIME: ${attachment.mimeType}`,
          )
        );
        continue;
      }

      // Double extension: invoice.pdf.exe
      if (DOUBLE_EXTENSION_RE.test(attachment.filename.toLowerCase())) {
        const parts = attachment.filename.split(".");
        const realExt = "." + parts.at(-1)!;
        if (HIGH_RISK_EXTENSIONS.has(realExt)) {
          score = Math.max(score, 90);
          signals.push(
            this.signal(
              "DOUBLE_EXTENSION_ATTACK",
              "Double extension file — uses benign-looking extension to hide executable payload",
              "CRITICAL",
              `Filename: ${safeFilename} (true extension: ${realExt})`,
            )
          );
          continue;
        }
      }

      // Container wrapping high-risk content (based on filename hint only)
      if (CONTAINER_EXTENSIONS.has(ext)) {
        score = Math.max(score, 30);
        signals.push(
          this.signal(
            "CONTAINER_ATTACHMENT",
            "Archive or disk image attachment — commonly used to wrap malicious executables and bypass extension filters",
            "MEDIUM",
            `Filename: ${safeFilename} (${Math.round(attachment.sizeBytes / 1024)}KB)`,
          )
        );
      }

      // Oversized attachment that claims to be a simple document
      const docExtensions = new Set([".pdf", ".docx", ".xlsx", ".pptx", ".txt"]);
      if (docExtensions.has(ext) && attachment.sizeBytes > 10 * 1024 * 1024) {
        score = Math.max(score, 25);
        signals.push(
          this.signal(
            "OVERSIZED_DOCUMENT",
            "Document attachment is unusually large — may contain embedded macros or payloads",
            "MEDIUM",
            `Filename: ${safeFilename} (${Math.round(attachment.sizeBytes / 1024 / 1024)}MB)`,
          )
        );
      }
    }

    // ── HTML structural anomalies ─────────────────────────────────────────────
    if (context.body.htmlContent) {
      const html = context.body.htmlContent;

      // HTML present but no plain-text alternative — common evasion pattern
      if (!context.body.plainText || context.body.plainText.trim().length < 20) {
        score = Math.max(score, 15);
        signals.push(
          this.signal(
            "HTML_ONLY_NO_PLAINTEXT",
            "Email contains HTML but no plain-text part — security scanners often rely on plain-text analysis",
            "LOW",
            "multipart/alternative with empty or missing text/plain part",
          )
        );
      }

      // Deep MIME nesting approximation via counting multipart boundaries in HTML
      const boundaryCount = (html.match(/Content-Type:\s*multipart/gi) ?? []).length;
      if (boundaryCount > 5) {
        score = Math.max(score, 30);
        signals.push(
          this.signal(
            "MIME_DEEP_NESTING",
            "Deeply nested MIME structure detected — obfuscation technique to confuse email security gateways",
            "MEDIUM",
            `${boundaryCount} nested multipart sections detected`,
          )
        );
      }

      // HTML smuggling in body (redundant with URLScanner but ContentStructureScanner owns structural analysis)
      const smuggling = detectHtmlSmuggling(html);
      if (smuggling.found) {
        score = Math.max(score, 90);
        for (const match of smuggling.matches) {
          const alreadySignaled = signals.some((s) => s.signalId === match.signalId);
          if (!alreadySignaled) {
            signals.push(
              this.signal(
                match.signalId,
                match.description,
                "CRITICAL",
                "HTML payload-reconstruction primitive detected — used in HTML Smuggling attacks",
              )
            );
          }
        }
      }

      // Suspicious inline styles that can hide content from scanners (zero-font tricks)
      if (/font-size:\s*0(px|pt|em)?/i.test(html) || /display:\s*none/i.test(html)) {
        score = Math.max(score, 20);
        signals.push(
          this.signal(
            "HIDDEN_CONTENT_CSS",
            "CSS used to hide email content — may conceal secondary message from human viewers",
            "LOW",
            "font-size:0 or display:none detected in HTML",
          )
        );
      }
    }

    // ── Message structure heuristics ──────────────────────────────────────────

    // Suspicious X-Mailer or missing standard headers
    const xMailer = context.headers.get("x-mailer");
    const userAgent = context.headers.get("user-agent");
    const messageId = context.headers.get("message-id");

    if (!messageId) {
      score = Math.max(score, 20);
      signals.push(
        this.signal(
          "MISSING_MESSAGE_ID",
          "Email is missing Message-ID header — RFC 5322 non-compliant, often seen in spam/phishing infrastructure",
          "LOW",
          "Message-ID header absent",
        )
      );
    }

    return this.buildResult(score, signals);
  }
}
