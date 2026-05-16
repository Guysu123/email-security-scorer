import { describe, it, expect } from "vitest";
import {
  checkHomograph,
  checkTyposquat,
  checkSubdomainConfusion,
} from "../utils/punycode";

describe("checkTyposquat", () => {
  it("flags a one-char substitution on a known brand", () => {
    const r = checkTyposquat("paypa1.com");
    expect(r.isTyposquat).toBe(true);
    expect(r.matchedBrand).toBe("paypal.com");
    expect(r.distance).toBeLessThanOrEqual(2);
  });

  it("does not flag the exact brand domain", () => {
    expect(checkTyposquat("paypal.com").isTyposquat).toBe(false);
  });

  it("flags 0→o digit substitution", () => {
    expect(checkTyposquat("g00gle.com").isTyposquat).toBe(true);
  });

  it("does not flag an unrelated domain", () => {
    expect(checkTyposquat("example.com").isTyposquat).toBe(false);
  });

  it("flags hyphen-prefix typosquat: paypa1-security.com", () => {
    const r = checkTyposquat("paypa1-security.com");
    expect(r.isTyposquat).toBe(true);
    expect(r.matchedBrand).toBe("paypal.com");
  });

  it("flags rn→m visual substitution: arnazon.com ≈ amazon.com", () => {
    const r = checkTyposquat("arnazon.com");
    expect(r.isTyposquat).toBe(true);
    expect(r.matchedBrand).toBe("amazon.com");
  });
});

describe("checkSubdomainConfusion", () => {
  it("detects brand as non-trailing subdomain", () => {
    expect(checkSubdomainConfusion("paypal.com.attacker.net")).toBe("paypal.com");
  });

  it("does not flag the actual brand domain", () => {
    expect(checkSubdomainConfusion("paypal.com")).toBeNull();
  });

  it("does not flag a legitimate subdomain of the brand", () => {
    expect(checkSubdomainConfusion("secure.paypal.com")).toBeNull();
  });
});

describe("checkHomograph", () => {
  it("returns non-homograph for a normal ASCII domain", () => {
    expect(checkHomograph("google.com").isHomograph).toBe(false);
  });

  it("detects punycode basics from xn-- labels", () => {
    // xn--pypal-4ve is the punycode encoding of paypal with a Cyrillic 'а'
    const r = checkHomograph("xn--pypal-4ve.com");
    expect(r.isHomograph).toBe(true);
    expect(r.matchedBrand).toBe("paypal.com");
  });
});
