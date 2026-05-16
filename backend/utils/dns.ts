// Reserved for future use: independent DNS-based SPF/DMARC verification.
// Currently unused — HeaderAuthScanner reads from the Authentication-Results header
// set by Gmail's MTA rather than performing its own DNS lookups.
import dns from "dns/promises";

export interface AuthRecord {
  spf: string | null;
  dmarc: string | null;
}

export async function fetchAuthRecords(domain: string): Promise<AuthRecord> {
  const [spfRecords, dmarcRecords] = await Promise.allSettled([
    dns.resolveTxt(domain),
    dns.resolveTxt(`_dmarc.${domain}`),
  ]);

  const spfFlat = spfRecords.status === "fulfilled"
    ? spfRecords.value.flat().find((r) => r.startsWith("v=spf1")) ?? null
    : null;

  const dmarcFlat = dmarcRecords.status === "fulfilled"
    ? dmarcRecords.value.flat().find((r) => r.startsWith("v=DMARC1")) ?? null
    : null;

  return { spf: spfFlat, dmarc: dmarcFlat };
}
