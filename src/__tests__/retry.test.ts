import { computeBackoffDelayMs, sleep } from "../internal/retry";

describe("computeBackoffDelayMs", () => {
  it("honors a numeric Retry-After header (seconds)", () => {
    expect(computeBackoffDelayMs(0, "2")).toBe(2000);
  });

  it("honors an HTTP-date Retry-After header", () => {
    const future = new Date(Date.now() + 5000).toUTCString();
    const delay = computeBackoffDelayMs(0, future);
    expect(delay).toBeGreaterThan(3000);
    expect(delay).toBeLessThanOrEqual(5000);
  });

  it("falls back to exponential backoff when no Retry-After is given", () => {
    const attempt0 = computeBackoffDelayMs(0, null);
    const attempt3 = computeBackoffDelayMs(3, null);
    expect(attempt0).toBeGreaterThan(0);
    expect(attempt3).toBeGreaterThan(attempt0);
  });

  it("caps the exponential delay so retries don't stall for minutes", () => {
    const delay = computeBackoffDelayMs(20, null);
    expect(delay).toBeLessThan(11_000);
  });

  it("ignores a garbage Retry-After value and falls back to backoff", () => {
    const delay = computeBackoffDelayMs(0, "not-a-date");
    expect(delay).toBeGreaterThan(0);
  });
});

describe("sleep", () => {
  it("resolves after the given delay", async () => {
    await expect(sleep(1)).resolves.toBeUndefined();
  });

  it("rejects immediately if the signal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort(new Error("cancelled"));
    await expect(sleep(1000, controller.signal)).rejects.toThrow("cancelled");
  });

  it("rejects when aborted mid-sleep", async () => {
    const controller = new AbortController();
    const promise = sleep(5000, controller.signal);
    controller.abort(new Error("cancelled mid-flight"));
    await expect(promise).rejects.toThrow("cancelled mid-flight");
  });
});
