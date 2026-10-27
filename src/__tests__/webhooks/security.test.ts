import crypto from "node:crypto";
import { verifyWebhookSignature } from "../../webhooks/signature";
import { DiditConfigurationError, DiditWebhookSignatureError } from "../../errors";

const secret = "security-fixture-secret";
const timestamp = 1_793_030_000;
const options = { secret, now: () => timestamp * 1000 };
const sign = (body: string): string =>
  crypto.createHmac("sha256", secret).update(body).digest("hex");

describe("full-payload webhook authentication", () => {
  it("rejects replaying an old signed body with a fresh unsigned timestamp header", () => {
    const body = JSON.stringify({ timestamp: timestamp - 600, decision: { status: "Approved" } });
    expect(() =>
      verifyWebhookSignature(
        body,
        { "x-signature": sign(body), "x-timestamp": String(timestamp) },
        options,
      ),
    ).toThrow(DiditWebhookSignatureError);
  });

  it("rejects Simple signatures that leave decisions unauthenticated", () => {
    const body = JSON.stringify({
      timestamp,
      session_id: "session",
      status: "Approved",
      webhook_type: "status.updated",
      decision: { status: "Declined" },
    });
    expect(() =>
      verifyWebhookSignature(
        body,
        {
          "x-signature-simple": sign(`${timestamp}:session:Approved:status.updated`),
          "x-timestamp": String(timestamp),
        },
        options,
      ),
    ).toThrow(DiditWebhookSignatureError);
  });

  it("authenticates numeric object keys in lexicographic order and preserves __proto__", () => {
    const body = `{"timestamp":${timestamp},"metadata":{"2":{},"10":{"__proto__":{"safe":true}}}}`;
    const canonical = `{"metadata":{"10":{"__proto__":{"safe":true}},"2":{}},"timestamp":${timestamp}}`;
    expect(
      verifyWebhookSignature(
        body,
        { "x-signature-v2": sign(canonical), "x-timestamp": String(timestamp) },
        options,
      ).verifiedWith,
    ).toBe("v2");
  });

  it("accepts the previous-secret header during signing-secret rotation", () => {
    const body = JSON.stringify({ timestamp });
    expect(
      verifyWebhookSignature(
        body,
        { "x-signature-previous": sign(body), "x-timestamp": String(timestamp) },
        options,
      ).verifiedWith,
    ).toBe("raw");
  });

  it("accepts freshness from the signed body without an unsigned timestamp header", () => {
    const body = JSON.stringify({ timestamp });
    expect(verifyWebhookSignature(body, { "x-signature": sign(body) }, options).verifiedWith).toBe(
      "raw",
    );
  });

  it.each(["1793030000junk", "1793030000.0", "1.79303e9"])(
    "rejects malformed timestamp header %s",
    (header) => {
      const body = JSON.stringify({ timestamp });
      expect(() =>
        verifyWebhookSignature(body, { "x-signature": sign(body), "x-timestamp": header }, options),
      ).toThrow(DiditWebhookSignatureError);
    },
  );

  it("rejects conflicting duplicated headers", () => {
    const body = JSON.stringify({ timestamp });
    expect(() =>
      verifyWebhookSignature(
        body,
        {
          "x-signature": sign(body),
          "x-timestamp": String(timestamp),
          "X-Timestamp": String(timestamp + 1),
        },
        options,
      ),
    ).toThrow(DiditWebhookSignatureError);
  });

  it.each([NaN, Infinity, -1])("rejects invalid tolerance %s", (toleranceSeconds) => {
    const body = JSON.stringify({ timestamp });
    expect(() =>
      verifyWebhookSignature(
        body,
        { "x-signature": sign(body), "x-timestamp": String(timestamp) },
        { ...options, toleranceSeconds },
      ),
    ).toThrow(DiditConfigurationError);
  });
});
