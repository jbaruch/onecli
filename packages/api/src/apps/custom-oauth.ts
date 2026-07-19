import type { AppDefinition } from "./types";
import { assertSafeOAuthHost, assertSafeOAuthUrl } from "./custom-oauth-ssrf";

/**
 * Generic OAuth 2.0 app (#365). Instead of a compiled-in provider, the
 * operator supplies the authorize URL, token URL, API host, scopes, and client
 * credentials as connection config. `buildAuthUrl` / `exchangeCode` are the
 * standard authorization-code flow (cf. `linkedin.ts`), parameterized on those
 * config values.
 *
 * Config lives in `AppConfig` (via `configurable`): the URLs/host/scopes/clientId
 * are non-secret (`settings`), the client secret is encrypted (`credentials`).
 * `exchangeCode` also persists `token_url` + `api_host` onto the resulting
 * connection so the Rust gateway can refresh and inject for a provider it has no
 * compiled-in `RefreshConfig` / host rule for (see gateway `apps.rs`).
 *
 * One custom-OAuth app per project — `AppConfig` is unique per (project,
 * provider). Multiple distinct custom apps would need a schema change; deferred
 * pending the #365 "one-instance vs many" decision.
 */

interface TokenResponse {
  access_token?: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  error?: string;
  error_description?: string;
}

function splitScopes(raw: string | undefined): string[] {
  return (raw ?? "").split(/[\s,]+/).filter(Boolean);
}

// Some OAuth providers front their token endpoint with a WAF (e.g. Cloudflare
// on api.trakt.tv) that 403s requests without a browser-like User-Agent. Send
// one on the server-side token exchange so it isn't blocked.
const TOKEN_REQUEST_USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

export const customOauth: AppDefinition = {
  id: "custom-oauth",
  name: "Custom OAuth",
  icon: "/icons/custom-oauth.svg",
  description: "Connect any standards-compliant OAuth 2.0 API by URL.",
  connectionMethod: {
    type: "oauth",
    buildAuthUrl: ({ appCredentials, redirectUri, scopes, state }) => {
      const authorizeUrl = appCredentials.authorizeUrl;
      if (!authorizeUrl) {
        throw new Error("Custom OAuth: authorization URL not configured");
      }
      assertSafeOAuthUrl(authorizeUrl, "authorization URL");
      if (!appCredentials.clientId) {
        throw new Error("Custom OAuth: client ID not configured");
      }

      const configuredScopes = splitScopes(appCredentials.scopes);
      const effectiveScopes = configuredScopes.length
        ? configuredScopes
        : scopes;

      const url = new URL(authorizeUrl);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", appCredentials.clientId);
      url.searchParams.set("redirect_uri", redirectUri);
      if (effectiveScopes.length) {
        url.searchParams.set("scope", effectiveScopes.join(" "));
      }
      url.searchParams.set("state", state);
      return url.toString();
    },
    exchangeCode: async ({ appCredentials, callbackParams, redirectUri }) => {
      if (callbackParams.error) {
        throw new Error(
          `Custom OAuth authorization error: ${callbackParams.error} — ${callbackParams.error_description ?? "no description"}`,
        );
      }
      if (!callbackParams.code) {
        throw new Error("Custom OAuth callback missing authorization code");
      }

      const tokenUrl = appCredentials.tokenUrl;
      if (!tokenUrl) {
        throw new Error("Custom OAuth: token URL not configured");
      }
      assertSafeOAuthUrl(tokenUrl, "token URL");

      const apiHost = appCredentials.apiHost;
      if (!apiHost) {
        throw new Error("Custom OAuth: API host not configured");
      }
      assertSafeOAuthHost(apiHost, "API host");

      if (!appCredentials.clientId || !appCredentials.clientSecret) {
        throw new Error("Custom OAuth: client credentials not configured");
      }

      const tokenRes = await fetch(tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
          "User-Agent": TOKEN_REQUEST_USER_AGENT,
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: callbackParams.code,
          client_id: appCredentials.clientId,
          client_secret: appCredentials.clientSecret,
          redirect_uri: redirectUri,
        }),
      });

      if (!tokenRes.ok) {
        const errorBody = await tokenRes.text();
        throw new Error(
          `Custom OAuth token exchange failed: ${tokenRes.status} ${tokenRes.statusText} — ${errorBody}`,
        );
      }

      const tokenData = (await tokenRes.json()) as TokenResponse;
      if (tokenData.error || !tokenData.access_token) {
        throw new Error(
          tokenData.error_description ??
            tokenData.error ??
            "Custom OAuth: failed to exchange code for token",
        );
      }

      const expiresAt = tokenData.expires_in
        ? Math.floor(Date.now() / 1000) + tokenData.expires_in
        : undefined;

      const credentials: Record<string, unknown> = {
        access_token: tokenData.access_token,
        token_type: tokenData.token_type,
        expires_at: expiresAt,
        // Refresh/inject contract for the gateway — it has no compiled-in
        // config for a user-defined provider, so it reads these off the
        // connection. `assertSafe*` above bounds them before they are stored.
        token_url: tokenUrl,
        api_host: apiHost,
      };
      if (tokenData.refresh_token) {
        credentials.refresh_token = tokenData.refresh_token;
      }

      const grantedScopes = tokenData.scope
        ? splitScopes(tokenData.scope)
        : splitScopes(appCredentials.scopes);

      return { credentials, scopes: grantedScopes, metadata: { apiHost } };
    },
  },
  available: true,
  labelHint: 'e.g. "trakt", "my-api"',
  configurable: {
    hint: "Point at any standards-compliant OAuth 2.0 API. URLs must be https and publicly reachable.",
    fields: [
      {
        name: "authorizeUrl",
        label: "Authorization URL",
        description: "The provider's OAuth 2.0 authorization endpoint.",
        placeholder: "https://api.example.com/oauth/authorize",
      },
      {
        name: "tokenUrl",
        label: "Token URL",
        description: "The provider's OAuth 2.0 token endpoint.",
        placeholder: "https://api.example.com/oauth/token",
      },
      {
        name: "apiHost",
        label: "API Host",
        description:
          "Host the access token is attached to on outbound requests.",
        placeholder: "api.example.com",
      },
      {
        name: "scopes",
        label: "Scopes",
        description:
          "Space-separated OAuth scopes to request. Leave blank for scope-less providers (e.g. Trakt).",
        placeholder: "read write",
        optional: true,
      },
      {
        name: "clientId",
        label: "Client ID",
        placeholder: "your-oauth-client-id",
      },
      {
        name: "clientSecret",
        label: "Client Secret",
        placeholder: "your-oauth-client-secret",
        secret: true,
      },
    ],
  },
};
