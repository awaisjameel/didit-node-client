import { Logger, redact } from "../logger";

describe("redact", () => {
  it("redacts known sensitive keys regardless of case", () => {
    const result = redact({
      "x-api-key": "secret",
      Authorization: "Bearer x",
      ok: "keep-me",
    }) as Record<string, unknown>;
    expect(result["x-api-key"]).toBe("[REDACTED]");
    expect(result.Authorization).toBe("[REDACTED]");
    expect(result.ok).toBe("keep-me");
  });

  it("redacts nested objects and arrays", () => {
    const result = redact({ nested: { webhookSecret: "s" }, list: [{ apiKey: "a" }] }) as any;
    expect(result.nested.webhookSecret).toBe("[REDACTED]");
    expect(result.list[0].apiKey).toBe("[REDACTED]");
  });

  it("passes through primitives untouched", () => {
    expect(redact("hello")).toBe("hello");
    expect(redact(42)).toBe(42);
    expect(redact(null)).toBeNull();
  });
});

describe("Logger", () => {
  it("does not call the sink when disabled", () => {
    const sink = jest.fn();
    new Logger(false, sink).debug("hello");
    expect(sink).not.toHaveBeenCalled();
  });

  it("calls the sink with redacted meta when enabled", () => {
    const sink = jest.fn();
    new Logger(true, sink).debug("hello", { apiKey: "secret", ok: 1 });
    expect(sink).toHaveBeenCalledWith("hello", { apiKey: "[REDACTED]", ok: 1 });
  });

  it("calls the sink with no meta argument when none is provided", () => {
    const sink = jest.fn();
    new Logger(true, sink).debug("hello");
    expect(sink).toHaveBeenCalledWith("hello", undefined);
  });
});
