import { resolveConfig } from "../config";
import { DiditConfigurationError } from "../errors";

describe("resolveConfig", () => {
  const ENV = process.env;

  beforeEach(() => {
    process.env = { ...ENV };
    delete process.env.DIDIT_API_KEY;
    delete process.env.DIDIT_WEBHOOK_SECRET;
    delete process.env.DIDIT_BASE_URL;
  });

  afterAll(() => {
    process.env = ENV;
  });

  it("throws DiditConfigurationError when no apiKey is provided or configured", () => {
    expect(() => resolveConfig({})).toThrow(DiditConfigurationError);
  });

  it("accepts apiKey passed directly", () => {
    const config = resolveConfig({ apiKey: "key_123" });
    expect(config.apiKey).toBe("key_123");
  });

  it("falls back to DIDIT_API_KEY environment variable", () => {
    process.env.DIDIT_API_KEY = "env_key";
    const config = resolveConfig({});
    expect(config.apiKey).toBe("env_key");
  });

  it("prefers an explicit apiKey over the environment variable", () => {
    process.env.DIDIT_API_KEY = "env_key";
    const config = resolveConfig({ apiKey: "explicit_key" });
    expect(config.apiKey).toBe("explicit_key");
  });

  it("defaults baseUrl to the production verification endpoint", () => {
    const config = resolveConfig({ apiKey: "k" });
    expect(config.baseUrl).toBe("https://verification.didit.me");
  });

  it("strips trailing slashes from a custom baseUrl", () => {
    const config = resolveConfig({ apiKey: "k", baseUrl: "https://example.com/api///" });
    expect(config.baseUrl).toBe("https://example.com/api");
  });

  it("rejects an invalid baseUrl", () => {
    expect(() => resolveConfig({ apiKey: "k", baseUrl: "not-a-url" })).toThrow(
      DiditConfigurationError,
    );
  });

  it("rejects a non-positive timeout", () => {
    expect(() => resolveConfig({ apiKey: "k", timeout: 0 })).toThrow(DiditConfigurationError);
    expect(() => resolveConfig({ apiKey: "k", timeout: -5 })).toThrow(DiditConfigurationError);
  });

  it("rejects a negative or non-integer maxRetries", () => {
    expect(() => resolveConfig({ apiKey: "k", maxRetries: -1 })).toThrow(DiditConfigurationError);
    expect(() => resolveConfig({ apiKey: "k", maxRetries: 1.5 })).toThrow(DiditConfigurationError);
  });

  it("defaults timeout, maxRetries, and debug sensibly", () => {
    const config = resolveConfig({ apiKey: "k" });
    expect(config.timeout).toBe(15_000);
    expect(config.maxRetries).toBe(2);
    expect(config.debug).toBe(false);
  });

  it("builds a descriptive User-Agent including appInfo when provided", () => {
    const config = resolveConfig({ apiKey: "k", appInfo: "my-app/1.0.0" });
    expect(config.userAgent).toMatch(/^didit-node-client\/\d+\.\d+\.\d+ node\/.+ my-app\/1\.0\.0$/);
  });

  it("carries webhookSecret from config or environment", () => {
    expect(resolveConfig({ apiKey: "k", webhookSecret: "whsec" }).webhookSecret).toBe("whsec");
    process.env.DIDIT_WEBHOOK_SECRET = "env_whsec";
    expect(resolveConfig({ apiKey: "k" }).webhookSecret).toBe("env_whsec");
  });
});
