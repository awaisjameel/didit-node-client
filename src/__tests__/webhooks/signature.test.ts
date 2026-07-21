import crypto from "node:crypto";
import { verifyWebhookSignature } from "../../webhooks/signature";
import { DiditConfigurationError, DiditWebhookSignatureError } from "../../errors";

const SECRET = "whsec_test_secret";

function hmac(payload: string): string {
  return crypto.createHmac("sha256", SECRET).update(payload, "utf8").digest("hex");
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

describe("verifyWebhookSignature", () => {
  it("verifies via the raw-body (X-Signature) scheme", () => {
    const body = { session_id: "s_1", status: "Approved", webhook_type: "status.updated" };
    const rawBody = JSON.stringify(body);
    const timestamp = String(nowSeconds());

    const result = verifyWebhookSignature(
      rawBody,
      { "x-signature": hmac(rawBody), "x-timestamp": timestamp },
      { secret: SECRET },
    );

    expect(result.verifiedWith).toBe("raw");
    expect(result.event).toEqual(body);
    expect(result.isTest).toBe(false);
  });

  it("verifies via the canonical (X-Signature-V2) scheme against a hand-sorted payload", () => {
    // Deliberately out-of-order keys in the raw body; the canonical form sorts them.
    const rawBody = '{"status":"Approved","session_id":"s_1"}';
    const canonical = '{"session_id":"s_1","status":"Approved"}';
    const timestamp = String(nowSeconds());

    const result = verifyWebhookSignature(
      rawBody,
      { "x-signature-v2": hmac(canonical), "x-timestamp": timestamp },
      { secret: SECRET },
    );

    expect(result.verifiedWith).toBe("v2");
  });

  it("verifies via the envelope-only (X-Signature-Simple) scheme", () => {
    const body = { session_id: "s_1", status: "In Review", webhook_type: "status.updated" };
    const rawBody = JSON.stringify(body);
    const timestamp = String(nowSeconds());
    const envelope = `${timestamp}:s_1:In Review:status.updated`;

    const result = verifyWebhookSignature(
      rawBody,
      { "x-signature-simple": hmac(envelope), "x-timestamp": timestamp },
      { secret: SECRET },
    );

    expect(result.verifiedWith).toBe("simple");
  });

  it("succeeds if any one signature scheme is valid, even if another header is wrong", () => {
    const body = { session_id: "s_1", status: "Approved", webhook_type: "status.updated" };
    const rawBody = JSON.stringify(body);
    const timestamp = String(nowSeconds());

    const result = verifyWebhookSignature(
      rawBody,
      {
        "x-signature-v2": "not-a-valid-signature",
        "x-signature": hmac(rawBody),
        "x-timestamp": timestamp,
      },
      { secret: SECRET },
    );

    expect(result.verifiedWith).toBe("raw");
  });

  it("rejects a tampered body", () => {
    const rawBody = JSON.stringify({ session_id: "s_1", status: "Approved" });
    const timestamp = String(nowSeconds());
    const signature = hmac(rawBody);
    const tamperedBody = JSON.stringify({ session_id: "s_1", status: "Declined" });

    expect(() =>
      verifyWebhookSignature(
        tamperedBody,
        { "x-signature": signature, "x-timestamp": timestamp },
        { secret: SECRET },
      ),
    ).toThrow(DiditWebhookSignatureError);
  });

  it("rejects when no signature header is present", () => {
    const rawBody = JSON.stringify({ session_id: "s_1" });
    expect(() =>
      verifyWebhookSignature(rawBody, { "x-timestamp": String(nowSeconds()) }, { secret: SECRET }),
    ).toThrow(/No signature header found/);
  });

  it("rejects when the timestamp header is missing", () => {
    const rawBody = JSON.stringify({ session_id: "s_1" });
    expect(() =>
      verifyWebhookSignature(rawBody, { "x-signature": hmac(rawBody) }, { secret: SECRET }),
    ).toThrow(/X-Timestamp/);
  });

  it("rejects a stale timestamp outside the tolerance window", () => {
    const rawBody = JSON.stringify({ session_id: "s_1" });
    const staleTimestamp = String(nowSeconds() - 600); // 10 minutes old

    expect(() =>
      verifyWebhookSignature(
        rawBody,
        { "x-signature": hmac(rawBody), "x-timestamp": staleTimestamp },
        { secret: SECRET },
      ),
    ).toThrow(/stale/);
  });

  it("accepts a custom toleranceSeconds", () => {
    const rawBody = JSON.stringify({ session_id: "s_1" });
    const timestamp = String(nowSeconds() - 600);

    const result = verifyWebhookSignature(
      rawBody,
      { "x-signature": hmac(rawBody), "x-timestamp": timestamp },
      { secret: SECRET, toleranceSeconds: 3600 },
    );
    expect(result.verifiedWith).toBe("raw");
  });

  it("rejects a body that is not valid JSON", () => {
    const rawBody = "not json";
    expect(() =>
      verifyWebhookSignature(
        rawBody,
        { "x-signature": hmac(rawBody), "x-timestamp": String(nowSeconds()) },
        { secret: SECRET },
      ),
    ).toThrow(/not valid JSON/);
  });

  it("throws DiditConfigurationError when no secret is available anywhere", () => {
    const rawBody = JSON.stringify({ session_id: "s_1" });
    expect(() =>
      verifyWebhookSignature(rawBody, { "x-signature": "x", "x-timestamp": String(nowSeconds()) }),
    ).toThrow(DiditConfigurationError);
  });

  it("flags Business Console test deliveries via isTest", () => {
    const rawBody = JSON.stringify({ session_id: "s_1" });
    const timestamp = String(nowSeconds());

    const result = verifyWebhookSignature(
      rawBody,
      { "x-signature": hmac(rawBody), "x-timestamp": timestamp, "x-didit-test-webhook": "true" },
      { secret: SECRET },
    );

    expect(result.isTest).toBe(true);
  });

  it("accepts a Buffer for rawBody", () => {
    const rawBody = JSON.stringify({ session_id: "s_1" });
    const buffer = Buffer.from(rawBody, "utf8");
    const timestamp = String(nowSeconds());

    const result = verifyWebhookSignature(
      buffer,
      { "x-signature": hmac(rawBody), "x-timestamp": timestamp },
      { secret: SECRET },
    );

    expect(result.event).toEqual({ session_id: "s_1" });
  });

  it("accepts standard title-cased HTTP header names", () => {
    const rawBody = JSON.stringify({ session_id: "s_1" });
    const timestamp = String(nowSeconds());

    expect(
      verifyWebhookSignature(
        rawBody,
        { "X-Signature": hmac(rawBody), "X-Timestamp": timestamp },
        { secret: SECRET },
      ).verifiedWith,
    ).toBe("raw");
  });

  it("rejects signed JSON values that cannot be webhook events", () => {
    const rawBody = "null";
    expect(() =>
      verifyWebhookSignature(
        rawBody,
        { "x-signature": hmac(rawBody), "x-timestamp": String(nowSeconds()) },
        { secret: SECRET },
      ),
    ).toThrow(/must be a JSON object/);
  });

  it("uses an injectable clock for deterministic timestamp checks", () => {
    const rawBody = JSON.stringify({ session_id: "s_1" });
    const fixedNowMs = 1_700_000_000_000;
    const timestamp = String(Math.floor(fixedNowMs / 1000));
    const signature = hmac(rawBody);
    const headers = { "x-signature": signature, "x-timestamp": timestamp };

    expect(
      verifyWebhookSignature(rawBody, headers, { secret: SECRET, now: () => fixedNowMs + 10_000 })
        .verifiedWith,
    ).toBe("raw");

    expect(() =>
      verifyWebhookSignature(rawBody, headers, { secret: SECRET, now: () => fixedNowMs + 600_000 }),
    ).toThrow(/stale/);
  });
});
