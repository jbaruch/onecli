import type { AppDefinition } from "./types";

// Trakt's OAuth endpoint rejects the bare HTTP-client user agent at its edge.
// Keep this value aligned with the gateway's TRAKT_USER_AGENT. Renewal owner:
// OneCLI Trakt maintainer; check Chromium Stable monthly and exercise refresh.
export const TRAKT_USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";

const requiredCredential = (
  fields: Record<string, string>,
  name: string,
): string => {
  const value = fields[name];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 4096 ||
    /[^!-~]/.test(value)
  ) {
    throw new Error(`Provide a valid Trakt ${name} before connecting.`);
  }
  return value;
};

export const trakt: AppDefinition = {
  id: "trakt",
  name: "Trakt",
  icon: "/icons/trakt.svg",
  description:
    "Movie and TV watch history, lists, ratings, and recommendations.",
  apiDocsUrl: "https://trakt.docs.apiary.io/",
  connectionMethod: {
    type: "credentials_import",
    fields: [
      {
        name: "clientId",
        label: "Client ID",
        placeholder: "Trakt application client ID",
        secret: true,
      },
      {
        name: "clientSecret",
        label: "Client secret",
        placeholder: "Trakt application client secret",
        secret: true,
      },
      {
        name: "accessToken",
        label: "Access token",
        placeholder: "Existing Trakt access token",
        secret: true,
      },
      {
        name: "refreshToken",
        label: "Refresh token",
        placeholder: "Existing Trakt refresh token",
        secret: true,
      },
    ],
    exchangeCredentials: async (fields) => {
      const clientId = requiredCredential(fields, "clientId");
      requiredCredential(fields, "clientSecret");
      const accessToken = requiredCredential(fields, "accessToken");
      const refreshToken = requiredCredential(fields, "refreshToken");
      // Validate the existing bearer without spending its single-use refresh
      // token. The gateway owns the first refresh after this import is stored.
      let profile: unknown;
      try {
        const response = await fetch("https://api.trakt.tv/users/settings", {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "trakt-api-key": clientId,
            "trakt-api-version": "2",
            "User-Agent": TRAKT_USER_AGENT,
          },
          signal: AbortSignal.timeout(10_000),
          redirect: "error",
        });
        if (!response.ok) {
          throw new Error(
            `Trakt connection validation failed (HTTP ${response.status}); check the existing access token and client ID.`,
          );
        }
        profile = await response.json();
      } catch (error) {
        if (
          error instanceof TypeError ||
          (error instanceof DOMException &&
            (error.name === "TimeoutError" || error.name === "AbortError"))
        ) {
          throw new Error(
            "Cannot reach Trakt to validate this connection. Check network access and retry; the refresh token was not used.",
          );
        }
        if (error instanceof SyntaxError) {
          throw new Error(
            "Trakt returned an unreadable profile; reconnect later.",
          );
        }
        throw error;
      }
      if (
        !profile ||
        typeof profile !== "object" ||
        !("user" in profile) ||
        !profile.user ||
        typeof profile.user !== "object" ||
        !("username" in profile.user) ||
        typeof profile.user.username !== "string" ||
        !profile.user.username ||
        profile.user.username.length > 200
      ) {
        throw new Error(
          "Trakt returned no usable account identity; reconnect later.",
        );
      }
      return {
        credentials: {
          access_token: accessToken,
          refresh_token: refreshToken,
          token_type: "Bearer",
          // The prior token's mint time is unknown. Force the first gateway
          // request through its locked, durable refresh instead of guessing.
          expires_at: 0,
          client_id: clientId,
          api_version: "2",
        },
        scopes: [],
        metadata: { username: profile.user.username },
      };
    },
  },
};
