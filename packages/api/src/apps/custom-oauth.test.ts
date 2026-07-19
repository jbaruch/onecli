import { afterEach, describe, expect, it, vi } from "vitest";
import { customOauth } from "./custom-oauth";

const method = customOauth.connectionMethod;
if (method.type !== "oauth") {
  throw new Error("custom-oauth connectionMethod must be oauth");
}

const APP_CREDS = {
  authorizeUrl: "https://api.trakt.tv/oauth/authorize",
  tokenUrl: "https://api.trakt.tv/oauth/token",
  apiHost: "api.trakt.tv",
  scopes: "read write",
  clientId: "client-abc",
  clientSecret: "secret-xyz",
};

describe("custom-oauth buildAuthUrl", () => {
  it("builds an authorization URL from config, using configured scopes", () => {
    const url = new URL(
      method.buildAuthUrl({
        appCredentials: APP_CREDS,
        redirectUri: "https://onecli.example/callback",
        scopes: ["ignored-route-default"],
        state: "state-123",
      }),
    );
    expect(url.origin + url.pathname).toBe(
      "https://api.trakt.tv/oauth/authorize",
    );
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("client-abc");
    expect(url.searchParams.get("redirect_uri")).toBe(
      "https://onecli.example/callback",
    );
    expect(url.searchParams.get("scope")).toBe("read write");
    expect(url.searchParams.get("state")).toBe("state-123");
  });

  it("rejects a non-https authorize URL (SSRF guard)", () => {
    expect(() =>
      method.buildAuthUrl({
        appCredentials: {
          ...APP_CREDS,
          authorizeUrl: "http://api.trakt.tv/oauth/authorize",
        },
        redirectUri: "https://onecli.example/callback",
        scopes: [],
        state: "s",
      }),
    ).toThrow(/must use https/);
  });

  it("throws when the authorize URL is missing", () => {
    expect(() =>
      method.buildAuthUrl({
        appCredentials: { ...APP_CREDS, authorizeUrl: "" },
        redirectUri: "https://onecli.example/callback",
        scopes: [],
        state: "s",
      }),
    ).toThrow(/authorization URL not configured/);
  });
});

describe("custom-oauth exchangeCode", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("exchanges a code and persists the refresh/inject contract", async () => {
    vi.spyOn(Date, "now").mockReturnValue(1_700_000_000_000);
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              access_token: "at-1",
              refresh_token: "rt-1",
              token_type: "bearer",
              expires_in: 7776000,
              scope: "read write",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          ),
      ),
    );

    const result = await method.exchangeCode({
      appCredentials: APP_CREDS,
      callbackParams: { code: "auth-code" },
      redirectUri: "https://onecli.example/callback",
    });

    expect(result.credentials.access_token).toBe("at-1");
    expect(result.credentials.refresh_token).toBe("rt-1");
    expect(result.credentials.expires_at).toBe(1_700_000_000 + 7776000);
    // The gateway reads these off the connection to refresh/inject a provider
    // it has no compiled-in config for.
    expect(result.credentials.token_url).toBe(
      "https://api.trakt.tv/oauth/token",
    );
    expect(result.credentials.api_host).toBe("api.trakt.tv");
    expect(result.scopes).toEqual(["read", "write"]);
    expect(result.metadata).toEqual({ apiHost: "api.trakt.tv" });
  });

  it("rejects a private token URL before making a request (SSRF guard)", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    await expect(
      method.exchangeCode({
        appCredentials: {
          ...APP_CREDS,
          tokenUrl: "https://169.254.169.254/token",
        },
        callbackParams: { code: "auth-code" },
        redirectUri: "https://onecli.example/callback",
      }),
    ).rejects.toThrow(/private or link-local/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("surfaces a provider error response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              error: "invalid_grant",
              error_description: "bad code",
            }),
            {
              status: 400,
              headers: { "Content-Type": "application/json" },
            },
          ),
      ),
    );
    await expect(
      method.exchangeCode({
        appCredentials: APP_CREDS,
        callbackParams: { code: "auth-code" },
        redirectUri: "https://onecli.example/callback",
      }),
    ).rejects.toThrow(/token exchange failed/);
  });

  it("errors when the callback carries an error", async () => {
    await expect(
      method.exchangeCode({
        appCredentials: APP_CREDS,
        callbackParams: { error: "access_denied" },
        redirectUri: "https://onecli.example/callback",
      }),
    ).rejects.toThrow(/authorization error/);
  });
});
