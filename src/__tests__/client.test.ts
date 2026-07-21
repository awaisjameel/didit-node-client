import { DiditClient } from "../client";
import { SessionsResource } from "../resources/sessions";
import { IdVerificationResource } from "../resources/id-verification";
import { WebhooksResource } from "../webhooks";
import { DiditConfigurationError } from "../errors";

describe("DiditClient", () => {
  it("throws DiditConfigurationError when constructed without an API key", () => {
    const original = process.env.DIDIT_API_KEY;
    delete process.env.DIDIT_API_KEY;

    expect(() => new DiditClient()).toThrow(DiditConfigurationError);

    if (original !== undefined) process.env.DIDIT_API_KEY = original;
  });

  it("wires up sessions, idVerification, and webhooks resources", () => {
    const client = new DiditClient({ apiKey: "test-key" });

    expect(client.sessions).toBeInstanceOf(SessionsResource);
    expect(client.idVerification).toBeInstanceOf(IdVerificationResource);
    expect(client.webhooks).toBeInstanceOf(WebhooksResource);
  });
});
