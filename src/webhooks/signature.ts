import crypto from "node:crypto";
import { DiditConfigurationError, DiditWebhookSignatureError } from "../errors";
import { canonicalJsonStringify } from "../internal/canonical-json";
import type {
  WebhookEvent,
  WebhookHeaders,
  WebhookSignatureScheme,
  WebhookVerificationResult,
} from "../types/webhook";

export interface VerifyWebhookOptions {
  /** Overrides the client's configured `webhookSecret` for this call. */
  secret?: string;
  /** Max allowed clock skew, in seconds, between now and `X-Timestamp`. Default `300`. */
  toleranceSeconds?: number;
  /** Injectable clock for testing. Defaults to `Date.now`. @internal */
  now?: () => number;
}

const DEFAULT_TOLERANCE_SECONDS = 300;

/**
 * Verifies and parses an inbound Didit webhook delivery.
 *
 * Didit signs every delivery with up to three headers (`X-Signature-V2`, `X-Signature`,
 * `X-Signature-Simple`); this checks whichever of them are present and accepts the payload
 * as soon as *any one* validates against your webhook secret with constant-time comparison.
 * Requests older than `toleranceSeconds` (default 5 minutes) are always rejected, even if
 * the signature is otherwise valid, to mitigate replay attacks.
 *
 * @param rawBody The exact bytes/string of the request body, **before** any JSON parsing —
 *   re-stringifying a parsed body can change whitespace/key order and break the raw-body and
 *   V2 signature checks. Use {@link createRawBodyMiddleware} (Express) or read the stream
 *   yourself to obtain this.
 * @throws {DiditWebhookSignatureError} if no signature header validates, the timestamp is
 *   missing/stale, or the body isn't valid JSON.
 * @throws {DiditConfigurationError} if no webhook secret was configured.
 */
export function verifyWebhookSignature(
  rawBody: string | Buffer,
  headers: WebhookHeaders,
  options: VerifyWebhookOptions = {},
): WebhookVerificationResult {
  const secret = options.secret ?? getConfiguredSecret();
  if (!secret) {
    throw new DiditConfigurationError(
      "A webhook secret is required to verify signatures. Pass `webhookSecret` to " +
        "`new DiditClient({ webhookSecret })`, set DIDIT_WEBHOOK_SECRET, or pass `{ secret }` " +
        "to this call directly.",
    );
  }

  const timestamp = getHeader(headers, "x-timestamp");
  if (!timestamp) {
    throw new DiditWebhookSignatureError("Missing required `X-Timestamp` header.");
  }
  assertFreshTimestamp(
    timestamp,
    options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS,
    options.now ?? Date.now,
  );

  const bodyBuffer = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, "utf8");
  const bodyString = bodyBuffer.toString("utf8");

  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyString);
  } catch {
    throw new DiditWebhookSignatureError("Webhook body is not valid JSON.");
  }
  if (!isRecord(parsed)) {
    throw new DiditWebhookSignatureError("Webhook body must be a JSON object.");
  }

  const signatureV2 = getHeader(headers, "x-signature-v2");
  const signatureRaw = getHeader(headers, "x-signature");
  const signatureSimple = getHeader(headers, "x-signature-simple");

  if (!signatureV2 && !signatureRaw && !signatureSimple) {
    throw new DiditWebhookSignatureError(
      "No signature header found (expected one of X-Signature-V2, X-Signature, X-Signature-Simple).",
    );
  }

  const verifiedWith = tryVerify({
    secret,
    signatureV2,
    signatureRaw,
    signatureSimple,
    bodyString,
    parsed,
    timestamp,
  });

  if (!verifiedWith) {
    throw new DiditWebhookSignatureError(
      "Webhook signature verification failed for all provided schemes.",
    );
  }

  return {
    event: parsed as WebhookEvent,
    verifiedWith,
    isTest: getHeader(headers, "x-didit-test-webhook") === "true",
  };
}

function tryVerify(input: {
  secret: string;
  signatureV2?: string;
  signatureRaw?: string;
  signatureSimple?: string;
  bodyString: string;
  parsed: Record<string, unknown>;
  timestamp: string;
}): WebhookSignatureScheme | undefined {
  const { secret, signatureV2, signatureRaw, signatureSimple, bodyString, parsed, timestamp } =
    input;

  if (
    signatureV2 &&
    constantTimeEqual(hmacHex(secret, canonicalJsonStringify(parsed)), signatureV2)
  ) {
    return "v2";
  }
  if (signatureRaw && constantTimeEqual(hmacHex(secret, bodyString), signatureRaw)) {
    return "raw";
  }
  if (signatureSimple) {
    const id = firstDefinedString(parsed, [
      "session_id",
      "business_session_id",
      "transaction_id",
      "vendor_user_id",
      "vendor_business_id",
    ]);
    const status = typeof parsed.status === "string" ? parsed.status : "";
    const webhookType = typeof parsed.webhook_type === "string" ? parsed.webhook_type : "";
    const envelope = `${timestamp}:${id ?? ""}:${status}:${webhookType}`;
    if (constantTimeEqual(hmacHex(secret, envelope), signatureSimple)) return "simple";
  }

  return undefined;
}

function firstDefinedString(record: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string") return value;
  }
  return undefined;
}

function assertFreshTimestamp(
  timestampHeader: string,
  toleranceSeconds: number,
  now: () => number,
): void {
  const incoming = Number.parseInt(timestampHeader, 10);
  if (!Number.isFinite(incoming)) {
    throw new DiditWebhookSignatureError(`Invalid \`X-Timestamp\` header: "${timestampHeader}".`);
  }
  const currentSeconds = Math.floor(now() / 1000);
  if (Math.abs(currentSeconds - incoming) > toleranceSeconds) {
    throw new DiditWebhookSignatureError(
      `Webhook timestamp is stale (received ${incoming}, now ${currentSeconds}, tolerance ${toleranceSeconds}s). ` +
        "This guards against replay attacks; if you're testing with a stored payload, pass a larger `toleranceSeconds`.",
    );
  }
}

function hmacHex(secret: string, payload: string): string {
  return crypto.createHmac("sha256", secret).update(payload, "utf8").digest("hex");
}

function constantTimeEqual(expectedHex: string, providedHex: string): boolean {
  const expected = Buffer.from(expectedHex, "utf8");
  const provided = Buffer.from(providedHex, "utf8");
  if (expected.length !== provided.length) return false;
  return crypto.timingSafeEqual(expected, provided);
}

function getHeader(headers: WebhookHeaders, name: string): string | undefined {
  for (const [headerName, value] of Object.entries(headers)) {
    if (headerName.toLowerCase() === name) return Array.isArray(value) ? value[0] : value;
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getConfiguredSecret(): string | undefined {
  return process.env.DIDIT_WEBHOOK_SECRET;
}
