import crypto from "node:crypto";
import { verifyWebhookSignature } from "../../webhooks/signature";
import { DiditConfigurationError, DiditWebhookSignatureError } from "../../errors";

const secret = "whsec_test_secret";
const timestamp = 1_793_030_000;
const options = { secret, now: () => timestamp * 1000 };
const hmac = (body: string | Buffer): string =>
  crypto.createHmac("sha256", secret).update(body).digest("hex");
const body = (extra: Record<string, unknown> = {}): string =>
  JSON.stringify({ timestamp, ...extra });

describe("verifyWebhookSignature", () => {
  it("verifies exact raw bytes and returns the payload", () => {
    const raw = body({ session_id: "s_1", status: "Approved" });
    const result = verifyWebhookSignature(raw, { "x-signature": hmac(raw) }, options);
    expect(result).toEqual({ event: JSON.parse(raw), verifiedWith: "raw", isTest: false });
  });

  it("verifies hand-sorted Unicode canonical JSON, lists and whole floats", () => {
    const raw = `{"timestamp":${timestamp},"status":"Approved","decision":{"z":1.0,"a":["Jos\u00e9",{},2]}}`;
    const canonical = `{"decision":{"a":["José",{},2],"z":1},"status":"Approved","timestamp":${timestamp}}`;
    expect(
      verifyWebhookSignature(raw, { "x-signature-v2": hmac(canonical) }, options).verifiedWith,
    ).toBe("v2");
  });

  it("checks raw signatures when the V2 signature is invalid", () => {
    const raw = body();
    expect(
      verifyWebhookSignature(
        raw,
        { "x-signature-v2": "invalid", "x-signature": hmac(raw) },
        options,
      ).verifiedWith,
    ).toBe("raw");
  });

  it("rejects a tampered body", () => {
    expect(() =>
      verifyWebhookSignature(
        body({ status: "Declined" }),
        { "x-signature": hmac(body({ status: "Approved" })) },
        options,
      ),
    ).toThrow(DiditWebhookSignatureError);
  });

  it("rejects missing full-payload signature headers", () => {
    expect(() => verifyWebhookSignature(body(), {}, options)).toThrow(/No signature header found/);
  });

  it("rejects a missing signed timestamp even with a fresh header", () => {
    const raw = '{"session_id":"s_1"}';
    expect(() =>
      verifyWebhookSignature(
        raw,
        { "x-signature": hmac(raw), "x-timestamp": String(timestamp) },
        options,
      ),
    ).toThrow(/timestamp/);
  });

  it("rejects stale signed timestamps", () => {
    const raw = body({ timestamp: timestamp - 600 });
    expect(() => verifyWebhookSignature(raw, { "x-signature": hmac(raw) }, options)).toThrow(
      /stale/,
    );
  });

  it("allows a finite custom tolerance", () => {
    const raw = body({ timestamp: timestamp - 600 });
    expect(
      verifyWebhookSignature(
        raw,
        { "x-signature": hmac(raw) },
        { ...options, toleranceSeconds: 3600 },
      ).verifiedWith,
    ).toBe("raw");
  });

  it("rejects invalid JSON", () => {
    expect(() =>
      verifyWebhookSignature("not JSON", { "x-signature": hmac("not JSON") }, options),
    ).toThrow(/not valid JSON/);
  });

  it("requires a configured secret", () => {
    const previous = process.env.DIDIT_WEBHOOK_SECRET;
    delete process.env.DIDIT_WEBHOOK_SECRET;
    try {
      expect(() => verifyWebhookSignature(body(), {})).toThrow(DiditConfigurationError);
    } finally {
      if (previous !== undefined) process.env.DIDIT_WEBHOOK_SECRET = previous;
    }
  });

  it("exposes the unsigned test-delivery hint", () => {
    const raw = body();
    expect(
      verifyWebhookSignature(
        raw,
        { "x-signature": hmac(raw), "x-didit-test-webhook": "true" },
        options,
      ).isTest,
    ).toBe(true);
  });

  it("accepts Buffers and case-insensitive hexadecimal signatures/headers", () => {
    const raw = Buffer.from(body());
    expect(
      verifyWebhookSignature(
        raw,
        { "X-Signature": hmac(raw).toUpperCase(), "X-Timestamp": String(timestamp) },
        options,
      ).verifiedWith,
    ).toBe("raw");
  });

  it.each(["null", "[]", "true", "1"])("rejects non-object JSON %s", (raw) => {
    expect(() => verifyWebhookSignature(raw, { "x-signature": hmac(raw) }, options)).toThrow(
      /must be a JSON object/,
    );
  });

  it("uses the injected clock for freshness", () => {
    const raw = body();
    expect(() =>
      verifyWebhookSignature(
        raw,
        { "x-signature": hmac(raw) },
        { ...options, now: () => (timestamp + 600) * 1000 },
      ),
    ).toThrow(/stale/);
  });

  it("rejects invalid UTF-8 instead of authenticating replacement characters", () => {
    const raw = Buffer.concat([
      Buffer.from(`{"timestamp":${timestamp},"name":"`),
      Buffer.from([0xff]),
      Buffer.from('"}'),
    ]);
    expect(() => verifyWebhookSignature(raw, { "x-signature": hmac(raw) }, options)).toThrow(
      /UTF-8/,
    );
  });

  it("sorts supplementary Unicode object keys by code point", () => {
    const raw = `{"timestamp":${timestamp},"metadata":{"😀":1,"\uE000":2}}`;
    const canonical = `{"metadata":{"\uE000":2,"😀":1},"timestamp":${timestamp}}`;
    expect(
      verifyWebhookSignature(raw, { "x-signature-v2": hmac(canonical) }, options).verifiedWith,
    ).toBe("v2");
  });

  it("supports signed legacy ISO creation timestamps", () => {
    const raw = JSON.stringify({ created_at: new Date(timestamp * 1000).toISOString() });
    expect(verifyWebhookSignature(raw, { "x-signature": hmac(raw) }, options).verifiedWith).toBe(
      "raw",
    );
  });
});
