/**
 * Static SSRF guard for user-supplied custom-OAuth endpoint URLs and hosts.
 *
 * A custom-OAuth app lets the operator point OneCLI at an arbitrary authorize
 * URL, token URL, and API host. The gateway will POST the client secret +
 * refresh token to the token URL and attach the bearer to requests for the API
 * host, so an unbounded value is an SSRF / credential-exfil surface.
 *
 * This module rejects the statically-detectable cases at config time: non-https
 * schemes and literal private / loopback / link-local / cloud-metadata / internal
 * hosts. It cannot catch a public hostname that *resolves* to a private address —
 * that connect-time guard lives in the gateway, which makes the actual request.
 */

/** IPv4 ranges that must never be an OAuth endpoint target. */
const PRIVATE_V4_RANGES: RegExp[] = [
  /^0\./, // "this" network
  /^10\./, // RFC1918
  /^127\./, // loopback
  /^169\.254\./, // link-local (incl. 169.254.169.254 cloud metadata)
  /^172\.(1[6-9]|2\d|3[0-1])\./, // RFC1918 172.16.0.0/12
  /^192\.168\./, // RFC1918
];

/** Internal-only hostname suffixes. */
const INTERNAL_SUFFIXES = [".internal", ".local", ".localhost"];

/**
 * Throw if `host` is one OneCLI must never treat as a public OAuth endpoint.
 * `host` may include a port, which is ignored.
 */
export function assertSafeOAuthHost(host: string, label: string): void {
  // Extract the bare host, dropping any port. IPv6 needs care: an unbracketed
  // address (`::1`, `fd00::1`) has multiple colons and no port, so a naive
  // `:port` strip would corrupt it.
  const trimmed = host.trim().toLowerCase();
  const bracketed = trimmed.match(/^\[([^\]]+)\]/); // [::1] or [::1]:443
  let bare: string;
  if (bracketed) {
    bare = bracketed[1] ?? trimmed;
  } else if ((trimmed.match(/:/g)?.length ?? 0) <= 1) {
    bare = trimmed.replace(/:\d+$/, ""); // hostname / IPv4, optional :port
  } else {
    bare = trimmed; // unbracketed IPv6 literal, no port
  }

  if (!bare) {
    throw new Error(`Custom OAuth: ${label} host is empty`);
  }
  if (bare === "localhost" || INTERNAL_SUFFIXES.some((s) => bare.endsWith(s))) {
    throw new Error(
      `Custom OAuth: ${label} host "${host}" is an internal name and is not allowed`,
    );
  }
  if (bare === "::1" || bare === "0:0:0:0:0:0:0:1") {
    throw new Error(
      `Custom OAuth: ${label} host "${host}" is loopback and is not allowed`,
    );
  }
  // IPv6 unique-local (fc00::/7) and link-local (fe80::/10).
  if (/^f[cd][0-9a-f]{2}:/.test(bare) || /^fe[89ab][0-9a-f]:/.test(bare)) {
    throw new Error(
      `Custom OAuth: ${label} host "${host}" is a private IPv6 address and is not allowed`,
    );
  }
  if (PRIVATE_V4_RANGES.some((re) => re.test(bare))) {
    throw new Error(
      `Custom OAuth: ${label} host "${host}" is a private or link-local address and is not allowed`,
    );
  }
}

/**
 * Throw if `raw` is not an https URL with a public host. Returns nothing;
 * callers use it as a guard before issuing a request to a user-supplied URL.
 */
export function assertSafeOAuthUrl(raw: string, label: string): void {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`Custom OAuth: ${label} "${raw}" is not a valid URL`);
  }
  if (url.protocol !== "https:") {
    throw new Error(
      `Custom OAuth: ${label} must use https (got "${url.protocol.replace(/:$/, "")}")`,
    );
  }
  assertSafeOAuthHost(url.hostname, label);
}
