interface RdapEvent {
  eventAction: string;
  eventDate: string;
}

interface RdapResponse {
  events?: RdapEvent[];
}

// Returns the domain's age in days via RDAP, or null on any lookup failure.
// Uses rdap.org as a unified gateway — no auth, no API key, JSON response.
export async function getDomainAgeDays(domain: string): Promise<number | null> {
  const root = domain.split(".").slice(-2).join(".");
  try {
    const resp = await fetch(`https://rdap.org/domain/${encodeURIComponent(root)}`, {
      signal: AbortSignal.timeout(4000),
      headers: { Accept: "application/rdap+json" },
    });
    if (!resp.ok) return null;
    const data = (await resp.json()) as RdapResponse;
    const regEvent = data.events?.find((e) => e.eventAction === "registration");
    if (!regEvent?.eventDate) return null;
    const ageDays = Math.floor((Date.now() - new Date(regEvent.eventDate).getTime()) / 86_400_000);
    return ageDays >= 0 ? ageDays : null;
  } catch {
    return null;
  }
}
