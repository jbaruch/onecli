import { describe, expect, it } from "vitest";
import { assertSafeOAuthHost, assertSafeOAuthUrl } from "./custom-oauth-ssrf";

describe("assertSafeOAuthUrl", () => {
  it("accepts a public https URL", () => {
    expect(() =>
      assertSafeOAuthUrl("https://api.trakt.tv/oauth/token", "token URL"),
    ).not.toThrow();
  });

  it("rejects non-https schemes", () => {
    expect(() =>
      assertSafeOAuthUrl("http://api.trakt.tv/oauth/token", "token URL"),
    ).toThrow(/must use https/);
  });

  it("rejects a malformed URL", () => {
    expect(() => assertSafeOAuthUrl("not-a-url", "token URL")).toThrow(
      /not a valid URL/,
    );
  });

  it("rejects the cloud-metadata endpoint", () => {
    expect(() =>
      assertSafeOAuthUrl("https://169.254.169.254/token", "token URL"),
    ).toThrow(/private or link-local/);
  });

  it("rejects RFC1918 hosts", () => {
    for (const host of ["10.0.0.5", "192.168.1.1", "172.16.9.9"]) {
      expect(() =>
        assertSafeOAuthUrl(`https://${host}/token`, "token URL"),
      ).toThrow(/private or link-local/);
    }
  });

  it("rejects loopback and internal names", () => {
    expect(() =>
      assertSafeOAuthUrl("https://localhost/token", "token URL"),
    ).toThrow(/internal name/);
    expect(() =>
      assertSafeOAuthUrl("https://vault.internal/token", "token URL"),
    ).toThrow(/internal name/);
    expect(() =>
      assertSafeOAuthUrl("https://127.0.0.1/token", "token URL"),
    ).toThrow(/private or link-local/);
  });
});

describe("assertSafeOAuthHost", () => {
  it("accepts a public host and ignores the port", () => {
    expect(() =>
      assertSafeOAuthHost("api.trakt.tv:443", "API host"),
    ).not.toThrow();
  });

  it("rejects private IPv6 (unique-local and link-local)", () => {
    expect(() => assertSafeOAuthHost("[fd00::1]", "API host")).toThrow(
      /private IPv6/,
    );
    expect(() => assertSafeOAuthHost("fe80::1", "API host")).toThrow(
      /private IPv6/,
    );
  });

  it("rejects IPv6 loopback", () => {
    expect(() => assertSafeOAuthHost("::1", "API host")).toThrow(/loopback/);
  });

  it("rejects an empty host", () => {
    expect(() => assertSafeOAuthHost("", "API host")).toThrow(/is empty/);
  });
});
