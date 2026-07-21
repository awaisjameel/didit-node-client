import crypto from "node:crypto";
import { WebhooksResource } from "../../webhooks";
import type { ResolvedConfig } from "../../config";
import { DiditConfigurationError } from "../../errors";

function config(overrides: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    apiKey: "k",
    baseUrl: "https://verification.didit.me",
    timeout: 15_000,
    maxRetries: 2,
    debug: false,
    userAgent: "ua",
    ...overrides,
  };
}

describe("WebhooksResource", () => {
  it("uses the client's configured webhookSecret by default", () => {
    const secret = "whsec_from_client";
    const resource = new WebhooksResource(config({ webhookSecret: secret }));
    const body = JSON.stringify({ session_id: "s_1", status: "Approved" });
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = crypto.createHmac("sha256", secret).update(body, "utf8").digest("hex");

    const result = resource.constructEvent(body, {
      "x-signature": signature,
      "x-timestamp": timestamp,
    });
    expect(result.verifiedWith).toBe("raw");
  });

  it("throws DiditConfigurationError when the client has no webhookSecret configured", () => {
    const resource = new WebhooksResource(config());
    const body = JSON.stringify({ session_id: "s_1" });
    expect(() =>
      resource.constructEvent(body, {
        "x-signature": "x",
        "x-timestamp": String(Math.floor(Date.now() / 1000)),
      }),
    ).toThrow(DiditConfigurationError);
  });

  it("allows overriding the secret per call", () => {
    const resource = new WebhooksResource(config({ webhookSecret: "wrong-secret" }));
    const secret = "override-secret";
    const body = JSON.stringify({ session_id: "s_1" });
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = crypto.createHmac("sha256", secret).update(body, "utf8").digest("hex");

    const result = resource.constructEvent(
      body,
      { "x-signature": signature, "x-timestamp": timestamp },
      { secret },
    );
    expect(result.verifiedWith).toBe("raw");
  });
});
