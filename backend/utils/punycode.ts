// High-value brand domains to check homographs and typosquatting against
export const BRAND_DOMAINS = [
  "google.com", "gmail.com", "microsoft.com", "outlook.com", "live.com",
  "apple.com", "icloud.com", "amazon.com", "paypal.com", "ebay.com",
  "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
  "dropbox.com", "box.com", "salesforce.com", "docusign.com",
  "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
];

// Levenshtein distance
function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

// Decode a domain through the WHATWG URL API to resolve any punycode/IDN
function decodeDomain(domain: string): string {
  try {
    return new URL(`https://${domain}`).hostname;
  } catch {
    return domain;
  }
}

// Extract the ASCII basic characters from a punycode label (the part before the last hyphen)
// e.g. "xn--pypal-4ve" -> "pypal" (the Cyrillic-а substituted label for "paypal")
function extractPunycodeBasics(label: string): string | null {
  if (!label.toLowerCase().startsWith("xn--")) return null;
  const inner = label.slice(4); // strip "xn--"
  const lastHyphen = inner.lastIndexOf("-");
  if (lastHyphen <= 0) return null; // no basics, only encoded chars
  return inner.slice(0, lastHyphen).toLowerCase();
}

export interface HomographResult {
  isHomograph: boolean;
  matchedBrand: string | null;
  decodedDomain: string;
}

export function checkHomograph(domain: string): HomographResult {
  const decoded = decodeDomain(domain);
  const decodedBase = decoded.replace(/\.[^.]+$/, "").toLowerCase();

  // Path 1: URL API decoded to Unicode (browser behaviour) — exact brand match
  if (decoded !== domain) {
    for (const brand of BRAND_DOMAINS) {
      if (decoded === brand || decoded.endsWith(`.${brand}`)) {
        return { isHomograph: true, matchedBrand: brand, decodedDomain: decoded };
      }
      const brandBase = brand.replace(/\.[^.]+$/, "");
      if (decodedBase !== brandBase && levenshtein(decodedBase, brandBase) <= 2) {
        return { isHomograph: true, matchedBrand: brand, decodedDomain: decoded };
      }
    }
  }

  // Path 2: Node.js keeps punycode form — extract ASCII basics from each xn-- label
  // e.g. "xn--pypal-4ve" → basics="pypal" which is Levenshtein-1 from "paypal"
  const labels = domain.split(".");
  for (const label of labels) {
    const basics = extractPunycodeBasics(label);
    if (!basics) continue;
    for (const brand of BRAND_DOMAINS) {
      const brandBase = brand.replace(/\.[^.]+$/, "");
      if (levenshtein(basics, brandBase) <= 2) {
        return { isHomograph: true, matchedBrand: brand, decodedDomain: decoded };
      }
    }
  }

  return { isHomograph: false, matchedBrand: null, decodedDomain: decoded };
}

export interface TyposquatResult {
  isTyposquat: boolean;
  matchedBrand: string | null;
  distance: number;
}

// Common visual character substitutions attackers use
const NORMALIZE_MAP: [RegExp, string][] = [
  [/rn/g, "m"],
  [/0/g, "o"],
  [/1/g, "l"],
  [/vv/g, "w"],
  [/5/g, "s"],
  [/3/g, "e"],
];

function normalize(s: string): string {
  let n = s.toLowerCase();
  for (const [from, to] of NORMALIZE_MAP) n = n.replace(from, to);
  return n;
}

export function checkTyposquat(domain: string): TyposquatResult {
  const domainBase = domain.replace(/\.[^.]+$/, "");
  const normalizedInput = normalize(domainBase);

  // Also check just the prefix before the first hyphen (e.g. "paypa1" from "paypa1-security")
  const hyphenPrefix = domainBase.includes("-") ? domainBase.split("-")[0] : null;
  const normalizedPrefix = hyphenPrefix ? normalize(hyphenPrefix) : null;

  let best: TyposquatResult = { isTyposquat: false, matchedBrand: null, distance: Infinity };

  for (const brand of BRAND_DOMAINS) {
    const brandBase = brand.replace(/\.[^.]+$/, "");
    const normalizedBrand = normalize(brandBase);

    if (domainBase === brandBase) continue; // exact match = legitimate

    const dist = levenshtein(normalizedInput, normalizedBrand);
    if (dist <= 2 && dist < best.distance) {
      best = { isTyposquat: true, matchedBrand: brand, distance: dist };
    }

    // Check hyphen prefix: catches "paypa1-security.com" → "paypa1" ≈ "paypal"
    if (normalizedPrefix && normalizedPrefix.length >= 4) {
      const prefixDist = levenshtein(normalizedPrefix, normalizedBrand);
      if (prefixDist <= 1 && prefixDist < best.distance) {
        best = { isTyposquat: true, matchedBrand: brand, distance: prefixDist };
      }
    }
  }

  return best;
}

// Detect subdomain confusion: paypal.com.attacker.net
export function checkSubdomainConfusion(domain: string): string | null {
  const lower = domain.toLowerCase();
  for (const brand of BRAND_DOMAINS) {
    // brand appears as a non-trailing segment
    if (lower.includes(brand + ".") && !lower.endsWith("." + brand) && lower !== brand) {
      return brand;
    }
  }
  return null;
}
