import { BaseScanner } from "./base";
import { EmailContext, ScannerResult, Signal } from "../lib/types";
import { checkHomograph, checkTyposquat, checkSubdomainConfusion } from "../utils/punycode";
import { detectHtmlSmuggling, extractUrls } from "../utils/html";
import { escapeHtml } from "../utils/html";

// Known URL shorteners and open redirectors commonly abused in phishing
const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "ow.ly", "short.link",
  "rebrand.ly", "cutt.ly", "rb.gy", "is.gd", "v.gd",
]);

// Common legitimate security vendor redirect patterns that attackers chain
const SECURITY_REDIRECTORS = [
  /safelinks\.protection\.outlook\.com/i,
  /urldefense\.proofpoint\.com/i,
  /urldefense\.com/i,
  /links\.protect\.cisco\.com/i,
];

function extractDomainFromUrl(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export class URLScanner extends BaseScanner {
  readonly id = "URLScanner";
  readonly displayName = "URL & Link Analysis";
  readonly weight = 0.20;
  readonly timeoutMs = 5000;

  protected async execute(context: EmailContext): Promise<ScannerResult> {
    const signals: Signal[] = [];
    let score = 0;

    // ── HTML Smuggling detection ──────────────────────────────────────────────
    if (context.body.htmlContent) {
      const smuggling = detectHtmlSmuggling(context.body.htmlContent);
      if (smuggling.found) {
        score = Math.max(score, 90);
        for (const match of smuggling.matches) {
          signals.push(
            this.signal(
              match.signalId,
              match.description,
              "CRITICAL",
              "JavaScript payload-reconstruction primitive detected in email HTML",
            )
          );
        }
      }
    }

    // ── URL extraction and analysis ───────────────────────────────────────────
    const allText = [
      context.body.plainText ?? "",
      context.body.htmlContent ?? "",
    ].join(" ");

    const urls = extractUrls(allText);

    if (urls.length === 0) {
      return this.buildResult(score, signals);
    }

    const seenDomains = new Set<string>();

    for (const url of urls.slice(0, 50)) { // cap at 50 URLs
      const domain = extractDomainFromUrl(url);
      if (!domain || seenDomains.has(domain)) continue;
      seenDomains.add(domain);

      // Homograph / Punycode attack
      const homograph = checkHomograph(domain);
      if (homograph.isHomograph && homograph.matchedBrand) {
        score = Math.max(score, 95);
        signals.push(
          this.signal(
            "HOMOGRAPH_ATTACK",
            `Domain uses Unicode lookalike characters to impersonate ${homograph.matchedBrand}`,
            "CRITICAL",
            escapeHtml(`${domain} → decoded: ${homograph.decodedDomain} (matches ${homograph.matchedBrand})`),
          )
        );
        continue;
      }

      // Subdomain confusion: paypal.com.evil.net
      const confused = checkSubdomainConfusion(domain);
      if (confused) {
        score = Math.max(score, 85);
        signals.push(
          this.signal(
            "SUBDOMAIN_CONFUSION",
            `Domain embeds trusted brand "${confused}" as a subdomain to create visual deception`,
            "CRITICAL",
            escapeHtml(`${domain} contains ${confused} as non-authoritative subdomain`),
          )
        );
        continue;
      }

      // Typosquatting
      const typo = checkTyposquat(domain);
      if (typo.isTyposquat && typo.matchedBrand) {
        score = Math.max(score, 70);
        signals.push(
          this.signal(
            "TYPOSQUATTING_DETECTED",
            `Domain is a likely typosquat of "${typo.matchedBrand}" (edit distance: ${typo.distance})`,
            "HIGH",
            escapeHtml(`${domain} ≈ ${typo.matchedBrand}`),
          )
        );
        continue;
      }

      // URL shortener — final destination unknown
      const rootDomain = domain.split(".").slice(-2).join(".");
      if (URL_SHORTENERS.has(rootDomain)) {
        score = Math.max(score, 30);
        signals.push(
          this.signal(
            "URL_SHORTENER",
            "Shortened URL detected — final destination cannot be verified without following redirect",
            "MEDIUM",
            escapeHtml(url.slice(0, 100)),
          )
        );
      }

      // Security vendor redirect chaining — attacker hides behind trusted redirector
      const isRedirectorChained = SECURITY_REDIRECTORS.some((re) => re.test(url));
      if (isRedirectorChained) {
        // Extract the nested URL from the redirector query string
        let nestedUrl: string | null = null;
        try {
          const parsed = new URL(url);
          nestedUrl = parsed.searchParams.get("url") ??
            parsed.searchParams.get("u") ??
            parsed.searchParams.get("link") ?? null;
        } catch {
          // ignore parse errors
        }
        if (nestedUrl) {
          const nestedDomain = extractDomainFromUrl(nestedUrl);
          if (nestedDomain) {
            const nestedTypo = checkTyposquat(nestedDomain);
            if (nestedTypo.isTyposquat && nestedTypo.matchedBrand) {
              score = Math.max(score, 85);
              signals.push(
                this.signal(
                  "OPEN_REDIRECT_CHAIN",
                  `Security vendor redirector wraps a typosquat domain — multi-layer URL obfuscation to evade scanners`,
                  "HIGH",
                  escapeHtml(`redirector → ${nestedDomain} ≈ ${nestedTypo.matchedBrand}`),
                )
              );
            }
          }
        }
      }
    }

    // Flag excessive URL count (spray pattern in phishing)
    if (urls.length > 20) {
      score = Math.max(score, 25);
      signals.push(
        this.signal(
          "EXCESSIVE_URL_COUNT",
          "Unusually high number of links in email — common in phishing campaigns",
          "MEDIUM",
          `${urls.length} URLs detected`,
        )
      );
    }

    return this.buildResult(score, signals);
  }
}
