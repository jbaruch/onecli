import { describe, expect, it } from "vitest";
import cases from "./corpus/google-write-cases.json";
import { classifyGoogleWrite } from "./google-write";
import { appTargetMatches } from "./translate/app-catalog";

describe("Google destructive writes share a fail-closed corpus with the live gateway", () => {
  it("requires destructive permission above the UTF-8 byte cap", () => {
    for (const description of ["x".repeat(1024 * 1024), "😀".repeat(300_000)]) {
      expect(
        classifyGoogleWrite(
          "google-calendar",
          "PATCH",
          "/calendar/v3/calendars/primary/events/fixture",
          JSON.stringify({ description }),
        ),
      ).toBe("destructive");
    }
  });

  it.each(cases)("$name", (test) => {
    expect(
      classifyGoogleWrite(test.provider, test.method, test.path, test.body),
    ).toBe(test.kind);
    const request = {
      host:
        test.provider === "gmail"
          ? "gmail.googleapis.com"
          : "www.googleapis.com",
      method: test.method,
      path: test.path,
      body: test.body ?? undefined,
      agentId: "fixture-agent",
      hasInjections: true,
      isLlmHost: false,
    };
    expect(
      appTargetMatches(request, test.provider, [test.ordinary], null),
    ).toBe(test.kind === "ordinary");
    expect(
      appTargetMatches(request, test.provider, [test.destructive], null),
    ).toBe(test.kind === "destructive");
  });
});
