import { describe, it, expect } from "vitest";
import { detectHtmlSmuggling, extractUrls, escapeHtml } from "../utils/html";

describe("detectHtmlSmuggling", () => {
  it("detects createObjectURL call", () => {
    const r = detectHtmlSmuggling('<script>URL.createObjectURL(blob)</script>');
    expect(r.found).toBe(true);
    expect(r.matches.some(m => m.signalId === "HTML_SMUGGLING_CREATE_OBJECT_URL")).toBe(true);
  });

  it("detects Blob constructor", () => {
    const r = detectHtmlSmuggling("new Blob([data])");
    expect(r.found).toBe(true);
    expect(r.matches.some(m => m.signalId === "HTML_SMUGGLING_BLOB_CONSTRUCTOR")).toBe(true);
  });

  it("detects atob base64 decode", () => {
    const r = detectHtmlSmuggling("var x = atob('aGVsbG8=')");
    expect(r.found).toBe(true);
    expect(r.matches.some(m => m.signalId === "HTML_SMUGGLING_BASE64_DECODE")).toBe(true);
  });

  it("detects script tag", () => {
    const r = detectHtmlSmuggling("<script src='evil.js'>");
    expect(r.found).toBe(true);
    expect(r.matches.some(m => m.signalId === "HTML_SCRIPT_TAG")).toBe(true);
  });

  it("returns no matches for clean HTML", () => {
    const r = detectHtmlSmuggling("<p>Hello, <strong>world</strong>.</p>");
    expect(r.found).toBe(false);
    expect(r.matches).toHaveLength(0);
  });
});

describe("extractUrls", () => {
  it("extracts http and https URLs from text", () => {
    const urls = extractUrls("Visit https://example.com and http://test.org");
    expect(urls).toContain("https://example.com");
    expect(urls).toContain("http://test.org");
  });

  it("deduplicates repeated URLs", () => {
    const urls = extractUrls("https://x.com https://x.com");
    expect(urls.filter(u => u === "https://x.com")).toHaveLength(1);
  });

  it("returns empty array for text with no URLs", () => {
    expect(extractUrls("no links here")).toHaveLength(0);
  });
});

describe("escapeHtml", () => {
  it("escapes angle brackets, quotes, and ampersands", () => {
    expect(escapeHtml('<script>alert("xss")</script>')).toBe(
      "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"
    );
  });

  it("escapes ampersands before other entities", () => {
    expect(escapeHtml("a&b")).toBe("a&amp;b");
  });

  it("leaves safe text unchanged", () => {
    expect(escapeHtml("hello world")).toBe("hello world");
  });
});
