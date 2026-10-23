import { countTopLevelLiteralKeys } from "./graphql";

export type GoogleWriteKind = "ordinary" | "destructive";

const MAX_BODY_BYTES = 1024 * 1024;
const invalidScalar = /[\uD800-\uDFFF]/u;

// JSON.parse accepts lone surrogates and overflowing numbers; serde_json does
// not. Bound both ports to the same scalar/depth domain before granting access.
function ordinaryJson(value: unknown): boolean {
  const pending: Array<[unknown, number]> = [[value, 1]];
  while (pending.length) {
    const [item, depth] = pending.pop()!;
    if (depth > 64) return false;
    if (typeof item === "number" && !Number.isFinite(item)) return false;
    if (typeof item === "string" && invalidScalar.test(item)) return false;
    if (item && typeof item === "object") {
      for (const [key, child] of Object.entries(item)) {
        if (invalidScalar.test(key)) return false;
        pending.push([child, depth + 1]);
      }
    }
  }
  return true;
}

// Only transport/projection options: body fields in a URL cannot escape review.
const safeOptions = new Set([
  "fields",
  "prettyPrint",
  "alt",
  "quotaUser",
  "key",
  "sendUpdates",
  "sendNotifications",
  "supportsAttachments",
  "conferenceDataVersion",
  "maxAttendees",
  "alwaysIncludeEmail",
]);

/** Twin of google_write.rs. Unreadable or ambiguous writes need destructive permission. */
export function classifyGoogleWrite(
  provider: string,
  method: string,
  path: string,
  body: string | undefined | null,
): GoogleWriteKind {
  if (
    method === "DELETE" ||
    (provider === "gmail" && path.split("?")[0]?.endsWith("/trash"))
  )
    return "destructive";
  const query = path.split("?")[1];
  if (
    query &&
    query.split("&").some((part) => !safeOptions.has(part.split("=")[0] ?? ""))
  )
    return "destructive";
  if (
    !body ||
    body.length > MAX_BODY_BYTES ||
    new TextEncoder().encode(body).byteLength > MAX_BODY_BYTES
  )
    return "destructive";
  let value: unknown;
  try {
    value = JSON.parse(body);
  } catch (error) {
    if (!(error instanceof SyntaxError)) throw error;
    return "destructive";
  }
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !ordinaryJson(value)
  )
    return "destructive";
  const record = value as Record<string, unknown>;
  if (provider === "google-calendar") {
    const count = countTopLevelLiteralKeys(body, "status");
    if (
      count < 0 ||
      count > 1 ||
      Object.keys(record).some(
        (key) => key.toLowerCase() === "status" && key !== "status",
      )
    )
      return "destructive";
    return record.status === undefined ||
      record.status === "confirmed" ||
      record.status === "tentative"
      ? "ordinary"
      : "destructive";
  }
  if (provider !== "gmail") return "destructive";
  const allowedKeys = new Set([
    "addLabelIds",
    "removeLabelIds",
    "add_label_ids",
    "remove_label_ids",
    "ids",
  ]);
  for (const [key, labels] of Object.entries(record)) {
    if (
      !allowedKeys.has(key) ||
      countTopLevelLiteralKeys(body, key) !== 1 ||
      !Array.isArray(labels) ||
      labels.some(
        (label: unknown) =>
          typeof label !== "string" || !/^[a-zA-Z0-9_-]+$/.test(label),
      )
    )
      return "destructive";
  }
  for (const [camel, snake] of [
    ["addLabelIds", "add_label_ids"],
    ["removeLabelIds", "remove_label_ids"],
  ] as const) {
    if (camel in record && snake in record) return "destructive";
  }
  const added = (record.addLabelIds ?? record.add_label_ids ?? []) as string[];
  return added.some((label) => label.toUpperCase() === "TRASH")
    ? "destructive"
    : "ordinary";
}
