import { afterEach, describe, expect, it, vi } from "vitest";
import { trakt, TRAKT_USER_AGENT } from "./trakt";

const method = trakt.connectionMethod;
if (method.type !== "credentials_import")
  throw new Error("expected credential import");

const fields = {
  clientId: "fixture-client",
  clientSecret: "fixture-secret",
  accessToken: "fixture-access",
  refreshToken: "fixture-refresh",
};

afterEach(() => vi.unstubAllGlobals());

describe("Trakt credential import", () => {
  it("validates with a read-only request and preserves the rotating token for the gateway", async () => {
    const fetch = vi.fn().mockResolvedValue(
      Response.json({
        user: { username: "fixture-user" },
        account: { token: "ignored" },
      }),
    );
    vi.stubGlobal("fetch", fetch);
    const result = await method.exchangeCredentials(fields);
    expect(fetch).toHaveBeenCalledOnce();
    expect(fetch).toHaveBeenCalledWith("https://api.trakt.tv/users/settings", {
      headers: {
        Authorization: "Bearer fixture-access",
        "trakt-api-key": "fixture-client",
        "trakt-api-version": "2",
        "User-Agent": TRAKT_USER_AGENT,
      },
      signal: expect.any(AbortSignal),
      redirect: "error",
    });
    expect(result).toEqual({
      credentials: {
        access_token: "fixture-access",
        refresh_token: "fixture-refresh",
        token_type: "Bearer",
        expires_at: 0,
        client_id: "fixture-client",
        api_version: "2",
      },
      scopes: [],
      metadata: { username: "fixture-user" },
    });
  });

  it.each(["clientId", "clientSecret", "accessToken", "refreshToken"])(
    "refuses missing %s before contacting Trakt",
    async (name) => {
      const fetch = vi.fn();
      vi.stubGlobal("fetch", fetch);
      await expect(
        method.exchangeCredentials({ ...fields, [name]: "" }),
      ).rejects.toThrow("Provide a valid Trakt");
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each(["with whitespace", "header\r\ninjection", "x".repeat(4097)])(
    "rejects unusable credential input without sending it",
    async (accessToken) => {
      const fetch = vi.fn();
      vi.stubGlobal("fetch", fetch);
      await expect(
        method.exchangeCredentials({ ...fields, accessToken }),
      ).rejects.toThrow("Provide a valid Trakt");
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it.each([401, 429, 500])(
    "rejects HTTP %s without reflecting the response",
    async (status) => {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue(new Response("private-response", { status })),
      );
      await expect(method.exchangeCredentials(fields)).rejects.toThrow(
        `HTTP ${status}`,
      );
      await expect(method.exchangeCredentials(fields)).rejects.not.toThrow(
        "private-response",
      );
    },
  );

  it.each([null, {}, { user: {} }, { user: { username: 1 } }])(
    "requires an actual account identity",
    async (profile) => {
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(Response.json(profile)));
      await expect(method.exchangeCredentials(fields)).rejects.toThrow(
        "no usable account identity",
      );
    },
  );

  it("reports malformed JSON without exposing its body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("private-response")),
    );
    await expect(method.exchangeCredentials(fields)).rejects.toThrow(
      "Trakt returned an unreadable profile; reconnect later.",
    );
  });

  it.each([
    new TypeError("private-transport-detail"),
    new DOMException("private-timeout-detail", "TimeoutError"),
    new DOMException("private-abort-detail", "AbortError"),
  ])(
    "gives actionable network recovery without reflecting private errors",
    async (error) => {
      vi.stubGlobal("fetch", vi.fn().mockRejectedValue(error));
      await expect(method.exchangeCredentials(fields)).rejects.toThrow(
        "Cannot reach Trakt to validate this connection. Check network access and retry; the refresh token was not used.",
      );
    },
  );

  it.each([
    new TypeError("private-body-transport-detail"),
    new DOMException("private-body-timeout-detail", "TimeoutError"),
  ])("reports recovery when reading the response body fails", async (error) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockRejectedValue(error),
      }),
    );
    await expect(method.exchangeCredentials(fields)).rejects.toThrow(
      "Cannot reach Trakt to validate this connection. Check network access and retry; the refresh token was not used.",
    );
  });

  it("preserves an unexpected connector defect", async () => {
    const defect = new RangeError("fixture-defect");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(defect));
    await expect(method.exchangeCredentials(fields)).rejects.toBe(defect);
  });
});
