import { BaseScanner } from "./base";
import { EmailContext, ScannerResult, Signal } from "../lib/types";

// Parses structured Authentication-Results header
interface AuthResult {
  spf: string | null;
  dkim: string | null;
  dmarc: string | null;
  dmarcPolicy: string | null;
}

function parseAuthResults(header: string | null): AuthResult {
  if (!header) return { spf: null, dkim: null, dmarc: null, dmarcPolicy: null };

  const extract = (key: string) =>
    header.match(new RegExp(`${key}=(\\w+)`, "i"))?.[1]?.toLowerCase() ?? null;

  const dmarcPolicy = header.match(/policy=(\w+)/i)?.[1]?.toLowerCase() ?? null;

  return {
    spf: extract("spf"),
    dkim: extract("dkim"),
    dmarc: extract("dmarc"),
    dmarcPolicy,
  };
}

export class HeaderAuthScanner extends BaseScanner {
  readonly id = "HeaderAuthScanner";
  readonly displayName = "Email Authentication";
  readonly weight = 0.30;
  readonly timeoutMs = 4000;

  protected async execute(context: EmailContext): Promise<ScannerResult> {
    const signals: Signal[] = [];
    let score = 0;

    // ── Parse Authentication-Results ─────────────────────────────────────────
    const authHeader = context.headers.get("authentication-results");
    const auth = parseAuthResults(authHeader);

    if (auth.dmarc === "fail") {
      score = Math.max(score, 85);
      signals.push(
        this.signal(
          "DMARC_FAIL",
          "DMARC policy fails — sender cannot be verified as the claimed domain owner",
          "CRITICAL",
          `dmarc=${auth.dmarc}${auth.dmarcPolicy ? ` (p=${auth.dmarcPolicy})` : ""}`,
        )
      );
    } else if (auth.dmarc === "softfail") {
      score = Math.max(score, 50);
      signals.push(
        this.signal(
          "DMARC_SOFTFAIL",
          "DMARC soft-fail — domain has a permissive policy that may allow spoofing",
          "HIGH",
          `dmarc=softfail`,
        )
      );
    } else if (auth.dmarc === "pass") {
      // Reward strong authentication — acts as natural score attenuator
    } else if (!auth.dmarc) {
      score = Math.max(score, 30);
      signals.push(
        this.signal(
          "DMARC_MISSING",
          "No DMARC authentication result found — email may not have been checked",
          "MEDIUM",
          "Authentication-Results header absent or malformed",
        )
      );
    }

    if (auth.dmarcPolicy === "none" && auth.dmarc !== "fail") {
      score = Math.max(score, 35);
      signals.push(
        this.signal(
          "DMARC_POLICY_NONE",
          "DMARC policy is 'none' — domain owner monitors but does not enforce authentication",
          "MEDIUM",
          "p=none (monitoring-only policy)",
        )
      );
    }

    if (auth.dkim === "fail") {
      score = Math.max(score, 55);
      signals.push(
        this.signal(
          "DKIM_FAIL",
          "DKIM signature verification failed — message content may have been tampered with in transit",
          "HIGH",
          "dkim=fail",
        )
      );
    }

    if (auth.spf === "fail" || auth.spf === "softfail") {
      const isSoft = auth.spf === "softfail";
      score = Math.max(score, isSoft ? 30 : 40);
      signals.push(
        this.signal(
          isSoft ? "SPF_SOFTFAIL" : "SPF_FAIL",
          isSoft
            ? "SPF soft-fail — sending server is not explicitly authorized by domain SPF record"
            : "SPF hard-fail — sending server is explicitly unauthorized by domain SPF record",
          isSoft ? "MEDIUM" : "HIGH",
          `spf=${auth.spf}`,
        )
      );
    }

    // ── DKIM alignment check ─────────────────────────────────────────────────
    // DKIM can pass but be misaligned (different domain than From header)
    const dkimHeader = context.headers.get("dkim-signature");
    if (dkimHeader && auth.dkim === "pass") {
      const dkimDomain = dkimHeader.match(/d=([^;\s]+)/i)?.[1]?.toLowerCase() ?? null;
      if (dkimDomain && dkimDomain !== context.sender.domain) {
        score = Math.max(score, 55);
        signals.push(
          this.signal(
            "DKIM_DOMAIN_MISMATCH",
            "DKIM signature passes but signs a different domain than the From address — common in phishing",
            "HIGH",
            `DKIM d=${dkimDomain}, From domain=${context.sender.domain}`,
          )
        );
      }
    }

    // ── Received chain analysis ───────────────────────────────────────────────
    const chain = context.receivedChain;

    if (chain.length === 0) {
      score = Math.max(score, 20);
      signals.push(
        this.signal(
          "RECEIVED_CHAIN_EMPTY",
          "No Received headers found — email may have been injected directly or headers stripped",
          "MEDIUM",
          "Received header count: 0",
        )
      );
    }

    // Timestamp inversion: earlier hop has later timestamp than later hop
    for (let i = 1; i < chain.length; i++) {
      const prev = chain[i - 1].timestamp;
      const curr = chain[i].timestamp;
      if (prev && curr && curr < prev) {
        score = Math.max(score, 35);
        signals.push(
          this.signal(
            "RECEIVED_TIMESTAMP_INVERSION",
            "Received header timestamps are out of order — indicates possible header manipulation",
            "MEDIUM",
            `Hop ${i}: ${curr.toISOString()} precedes hop ${i - 1}: ${prev.toISOString()}`,
          )
        );
        break;
      }
    }

    // SMTP smuggling indicator: bare LF (\n without \r) in raw header block
    // Legitimate MTAs always use CRLF; bare LF is a parser-differential exploit marker
    if (/(?<!\r)\n\.\n/.test(context.rawHeaders) || /\n\.\r\n/.test(context.rawHeaders)) {
      score = Math.max(score, 90);
      signals.push(
        this.signal(
          "SMTP_SMUGGLING_INDICATOR",
          "Bare LF end-of-data sequence detected — potential SMTP Smuggling attack exploiting MTA parser differentials",
          "CRITICAL",
          "Non-standard SMTP DATA terminator sequence found in message headers",
        )
      );
    }

    // Reply-To in a different country TLD than From (simple heuristic)
    const fromTld = context.sender.domain.split(".").at(-1) ?? "";
    const replyTld = context.sender.replyToDomain?.split(".").at(-1) ?? fromTld;
    if (
      context.sender.replyToDomain &&
      replyTld !== fromTld &&
      !["com", "org", "net", "edu"].includes(replyTld)
    ) {
      score = Math.max(score, 30);
      signals.push(
        this.signal(
          "REPLY_TO_FOREIGN_TLD",
          "Reply-To uses a different country TLD than the From address — possible geographic mismatch",
          "LOW",
          `From TLD: .${fromTld}, Reply-To TLD: .${replyTld}`,
        )
      );
    }

    return this.buildResult(score, signals);
  }
}
