import { describe, expect } from "vitest";
import { throughProxy } from "../src/proxy.js";
import { scenario } from "../src/scenario.js";

// Both outcomes stop at a block rule before opening an upstream socket. The
// named rule proves the real binary buffered and classified the request body.
const cases = [
  {
    name: "ordinary Gmail labels",
    provider: "gmail",
    host: "gmail.googleapis.com",
    method: "POST",
    path: "/gmail/v1/users/me/messages/a123/modify",
    body: '{"removeLabelIds":["INBOX"]}',
    destructive: false,
  },
  {
    name: "escaped Trash label",
    provider: "gmail",
    host: "gmail.googleapis.com",
    method: "POST",
    path: "/gmail/v1/users/me/messages/a123/modify",
    body: '{"addLabelIds":["TR\\u0041SH"]}',
    destructive: true,
  },
  {
    name: "Trash on the legacy host",
    provider: "gmail",
    host: "www.googleapis.com",
    method: "POST",
    path: "/gmail/v1/users/me/threads/a123/modify",
    body: '{"addLabelIds":["TRASH"]}',
    destructive: true,
  },
  {
    name: "batch Trash labels",
    provider: "gmail",
    host: "gmail.googleapis.com",
    method: "POST",
    path: "/gmail/v1/users/me/messages/batchModify",
    body: '{"ids":["a123"],"addLabelIds":["TRASH"]}',
    destructive: true,
  },
  {
    name: "duplicate label keys",
    provider: "gmail",
    host: "gmail.googleapis.com",
    method: "POST",
    path: "/gmail/v1/users/me/messages/a123/modify",
    body: '{"addLabelIds":["TRASH"],"addLabelIds":[]}',
    destructive: true,
  },
  {
    name: "ordinary Calendar update",
    provider: "google-calendar",
    host: "www.googleapis.com",
    method: "PATCH",
    path: "/calendar/v3/calendars/primary/events/fixture",
    body: '{"summary":"Changed"}',
    destructive: false,
  },
  {
    name: "Calendar cancellation through PATCH",
    provider: "google-calendar",
    host: "www.googleapis.com",
    method: "PATCH",
    path: "/calendar/v3/calendars/primary/events/fixture",
    body: '{"status":"cancelled"}',
    destructive: true,
  },
  {
    name: "Calendar cancellation through PUT",
    provider: "google-calendar",
    host: "www.googleapis.com",
    method: "PUT",
    path: "/calendar/v3/calendars/primary/events/fixture",
    body: '{"status":"canc\\u0065lled"}',
    destructive: true,
  },
  {
    name: "Gmail read",
    provider: "gmail",
    host: "gmail.googleapis.com",
    method: "GET",
    path: "/gmail/v1/users/me/messages/a123",
    body: undefined,
    destructive: false,
  },
  {
    name: "Calendar read",
    provider: "google-calendar",
    host: "www.googleapis.com",
    method: "GET",
    path: "/calendar/v3/calendars/primary/events/fixture",
    body: undefined,
    destructive: false,
  },
];

describe("Google destructive write discrimination through the native gateway", () => {
  for (const test of cases) {
    scenario(test.name, async (cx) => {
      await cx.seed({
        rules: [
          {
            name: "destructive-write",
            action: "block",
            targets: [
              {
                kind: "app",
                provider: test.provider,
                tools:
                  test.provider === "gmail"
                    ? ["trash_message", "trash_thread", "batch_trash_messages"]
                    : ["delete_event"],
              },
            ],
          },
          {
            name: "ordinary-fallthrough",
            action: "block",
            targets: [{ kind: "app", provider: test.provider }],
          },
        ],
      });
      const gateway = await cx.startGateway();
      const response = await throughProxy(gateway.origin, {
        method: test.method,
        url: `http://${test.host}${test.path}`,
        token: cx.ids.agentToken,
        headers: { "content-type": "application/json" },
        body: test.body,
      });
      expect(response.status).toBe(403);
      expect(response.json()).toMatchObject({
        error: "blocked_by_policy",
        rule_name: test.destructive
          ? "destructive-write"
          : "ordinary-fallthrough",
      });
    });
  }
});
