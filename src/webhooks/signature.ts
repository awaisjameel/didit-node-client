import crypto from "node:crypto";
import { isUtf8 } from "node:buffer";
import { DiditConfigurationError, DiditWebhookSignatureError } from "../errors";
import { canonicalJsonStringify } from "../internal/canonical-json";
import type { WebhookEvent, WebhookHeaders, WebhookVerificationResult } from "../types/webhook";

export interface VerifyWebhookOptions {
  /** Overrides the client's configured webhook secret for this call. */
  secret?: string;
  /** Max clock skew from the signed body timestamp, in seconds. Default 300. */
  toleranceSeconds?: number;
  /** Injectable clock in milliseconds. @internal */
  now?: () => number;
}

/**
 * Authenticate the complete payload with V2 canonical JSON or exact raw bytes.
 * Simple signatures are never accepted. Freshness must come from signed data;
 * an optional X-Timestamp header must agree with it. Previous-secret headers
 * support Didit's signing-secret rotation window.
 */
export function verifyWebhookSignature(
  rawBody: string | Buffer,
  headers: WebhookHeaders,
  options: VerifyWebhookOptions = {},
): WebhookVerificationResult {
  const secret = options.secret ?? process.env.DIDIT_WEBHOOK_SECRET;
  if (!secret) {
    throw new DiditConfigurationError("A webhook secret is required to verify signatures.");
  }
  const tolerance = options.toleranceSeconds ?? 300;
  const now = Math.floor((options.now ?? Date.now)() / 1000);
  if (!Number.isFinite(tolerance) || tolerance < 0 || !Number.isFinite(now)) {
    throw new DiditConfigurationError(
      "Webhook tolerance must be finite and non-negative, and the clock must be finite.",
    );
  }
  const body = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, "utf8");
  if (!isUtf8(body)) throw new DiditWebhookSignatureError("Webhook body is not valid UTF-8.");
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString("utf8"));
  } catch {
    throw new DiditWebhookSignatureError("Webhook body is not valid JSON.");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new DiditWebhookSignatureError("Webhook body must be a JSON object.");
  }
  const payload = parsed as Record<string, unknown>;
  const timestamp = Object.hasOwn(payload, "timestamp")
    ? unixTimestamp(payload.timestamp)
    : legacyTimestamp(payload.created_at);
  if (timestamp === undefined || Math.abs(now - timestamp) > tolerance) {
    throw new DiditWebhookSignatureError("Signed webhook timestamp is stale or invalid.");
  }
  const headerTimestamp = getHeader(headers, "x-timestamp");
  if (headerTimestamp !== undefined && unixTimestamp(headerTimestamp) !== timestamp) {
    throw new DiditWebhookSignatureError(
      "X-Timestamp does not match the signed payload timestamp.",
    );
  }
  const v2 = [getHeader(headers, "x-signature-v2"), getHeader(headers, "x-signature-v2-previous")];
  const raw = [getHeader(headers, "x-signature"), getHeader(headers, "x-signature-previous")];
  if (![...v2, ...raw].some(Boolean)) {
    throw new DiditWebhookSignatureError(
      "No signature header found; a full-payload V2 or raw signature is required.",
    );
  }
  let canonical: string;
  try {
    canonical = canonicalJsonStringify(payload);
  } catch {
    throw new DiditWebhookSignatureError("Webhook body cannot be canonicalized.");
  }
  const verifiedWith = matches(secret, canonical, v2)
    ? "v2"
    : matches(secret, body, raw)
      ? "raw"
      : undefined;
  if (!verifiedWith)
    throw new DiditWebhookSignatureError("Webhook full-payload signature verification failed.");
  return {
    event: payload as WebhookEvent,
    verifiedWith,
    isTest: getHeader(headers, "x-didit-test-webhook") === "true",
  };
}

function matches(
  secret: string,
  body: string | Buffer,
  signatures: Array<string | undefined>,
): boolean {
  const expected = crypto.createHmac("sha256", secret).update(body).digest();
  return signatures.some(
    (signature) =>
      signature !== undefined &&
      /^[a-f0-9]{64}$/i.test(signature) &&
      crypto.timingSafeEqual(expected, Buffer.from(signature, "hex")),
  );
}

function unixTimestamp(value: unknown): number | undefined {
  if (typeof value !== "number" && (typeof value !== "string" || !/^[0-9]+$/.test(value)))
    return undefined;
  const timestamp = Number(value);
  return Number.isSafeInteger(timestamp) ? timestamp : undefined;
}

function legacyTimestamp(value: unknown): number | undefined {
  const unix = unixTimestamp(value);
  if (unix !== undefined) return unix;
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
  )
    return undefined;
  const timestamp = Date.parse(value) / 1000;
  return Number.isFinite(timestamp) ? Math.floor(timestamp) : undefined;
}

function getHeader(headers: WebhookHeaders, name: string): string | undefined {
  let result: string | undefined;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name || value === undefined) continue;
    if (Array.isArray(value) && value.length !== 1)
      throw new DiditWebhookSignatureError(`Ambiguous webhook header: ${name}.`);
    const text = Array.isArray(value) ? value[0] : value;
    if (result !== undefined && result !== text)
      throw new DiditWebhookSignatureError(`Ambiguous webhook header: ${name}.`);
    result = text;
  }
  return result;
}
