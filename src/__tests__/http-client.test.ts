import axios from "axios";
import { HttpClient } from "../internal/http-client";
import { Logger } from "../logger";
import type { ResolvedConfig } from "../config";
import {
  DiditConnectionError,
  DiditRateLimitError,
  DiditServerError,
  DiditValidationError,
} from "../errors";

jest.mock("axios", () => ({
  __esModule: true,
  default: { create: jest.fn() },
  isAxiosError: (e: unknown): boolean =>
    !!(e && typeof e === "object" && (e as Record<string, unknown>).isAxiosError),
}));

const mockedAxios = axios as unknown as { create: jest.Mock };

function config(overrides: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    apiKey: "test-api-key",
    baseUrl: "https://verification.didit.me",
    timeout: 15_000,
    maxRetries: 2,
    debug: false,
    userAgent: "didit-node-client/test",
    ...overrides,
  };
}

function makeClient(overrides: Partial<ResolvedConfig> = {}, requestImpl?: jest.Mock) {
  const request = requestImpl ?? jest.fn();
  mockedAxios.create.mockReturnValue({ request });
  const client = new HttpClient(config(overrides), new Logger(false));
  return { client, request };
}

function response(status: number, data: unknown, headers: Record<string, unknown> = {}) {
  return { status, data, headers };
}

describe("HttpClient", () => {
  beforeEach(() => jest.clearAllMocks());

  it("sends x-api-key, User-Agent, and JSON content-type headers", async () => {
    const request = jest.fn().mockResolvedValue(response(200, { ok: true }));
    const { client } = makeClient({}, request);

    await client.request({ method: "GET", path: "/v3/session/x/decision/" });

    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({
        headers: expect.objectContaining({
          "x-api-key": "test-api-key",
          "User-Agent": "didit-node-client/test",
          "Content-Type": "application/json",
        }),
      }),
    );
  });

  it("returns parsed data, status, and lower-cased headers on 2xx", async () => {
    const request = jest
      .fn()
      .mockResolvedValue(response(201, { session_id: "s_1" }, { "X-Request-Id": "req_1" }));
    const { client } = makeClient({}, request);

    const result = await client.request<{ session_id: string }>({
      method: "POST",
      path: "/v3/session/",
    });

    expect(result.status).toBe(201);
    expect(result.data).toEqual({ session_id: "s_1" });
    expect(result.headers["x-request-id"]).toBe("req_1");
  });

  it("maps a 400 response to DiditValidationError with the API message", async () => {
    const request = jest
      .fn()
      .mockResolvedValue(response(400, { message: "workflow_id is invalid" }));
    const { client } = makeClient({}, request);

    await expect(client.request({ method: "POST", path: "/v3/session/" })).rejects.toThrow(
      DiditValidationError,
    );
    await expect(client.request({ method: "POST", path: "/v3/session/" })).rejects.toThrow(
      /workflow_id is invalid/,
    );
  });

  it("extracts DRF-style field errors into the message", async () => {
    const request = jest.fn().mockResolvedValue(response(400, { callback: ["Not a valid URL."] }));
    const { client } = makeClient({}, request);

    await expect(client.request({ method: "POST", path: "/v3/session/" })).rejects.toThrow(
      /callback: Not a valid URL\./,
    );
  });

  it("maps 429 to DiditRateLimitError and parses rate-limit headers", async () => {
    const request = jest.fn().mockResolvedValue(
      response(
        429,
        { message: "rate limited" },
        {
          "retry-after": "1",
          "x-ratelimit-limit": "600",
          "x-ratelimit-remaining": "0",
          "x-ratelimit-reset": "42",
        },
      ),
    );
    const { client } = makeClient({ maxRetries: 0 }, request);

    let caught: DiditRateLimitError | undefined;
    try {
      await client.request({ method: "POST", path: "/v3/session/", retry: false });
    } catch (error) {
      caught = error as DiditRateLimitError;
    }

    expect(caught).toBeInstanceOf(DiditRateLimitError);
    expect(caught?.retryAfter).toBe(1);
    expect(caught?.limit).toBe(600);
    expect(caught?.remaining).toBe(0);
  });

  it("decodes a JSON error body even when responseType is arraybuffer", async () => {
    const body = Buffer.from(JSON.stringify({ message: "session not eligible for PDF" }), "utf8");
    const request = jest.fn().mockResolvedValue(response(403, body));
    const { client } = makeClient({}, request);

    await expect(
      client.request({
        method: "GET",
        path: "/v3/session/x/generate-pdf/",
        responseType: "arraybuffer",
      }),
    ).rejects.toThrow(/session not eligible for PDF/);
  });

  it("wraps network failures in DiditConnectionError", async () => {
    const request = jest.fn().mockRejectedValue({
      isAxiosError: true,
      message: "getaddrinfo ENOTFOUND",
      code: "ENOTFOUND",
    });
    const { client } = makeClient({ maxRetries: 0 }, request);

    await expect(client.request({ method: "GET", path: "/v3/sessions/" })).rejects.toThrow(
      DiditConnectionError,
    );
  });

  it("labels a timeout as a timeout-specific DiditConnectionError message", async () => {
    const request = jest.fn().mockRejectedValue({
      isAxiosError: true,
      message: "timeout of 15000ms exceeded",
      code: "ECONNABORTED",
    });
    const { client } = makeClient({ maxRetries: 0 }, request);

    await expect(client.request({ method: "GET", path: "/v3/sessions/" })).rejects.toThrow(
      /timed out/,
    );
  });

  it("retries GET requests on 5xx up to maxRetries, then succeeds", async () => {
    const request = jest
      .fn()
      .mockResolvedValueOnce(response(503, { message: "unavailable" }))
      .mockResolvedValueOnce(response(200, { ok: true }));
    const { client } = makeClient({ maxRetries: 2 }, request);

    const result = await client.request<{ ok: boolean }>({ method: "GET", path: "/v3/sessions/" });

    expect(result.data).toEqual({ ok: true });
    expect(request).toHaveBeenCalledTimes(2);
  });

  it("gives up after exhausting retries and throws the last error", async () => {
    const request = jest.fn().mockResolvedValue(response(503, { message: "still down" }));
    const { client } = makeClient({ maxRetries: 2 }, request);

    await expect(client.request({ method: "GET", path: "/v3/sessions/" })).rejects.toThrow(
      DiditServerError,
    );
    expect(request).toHaveBeenCalledTimes(3); // initial attempt + 2 retries
  });

  it("does not retry POST/PATCH requests by default even on 5xx", async () => {
    const request = jest.fn().mockResolvedValue(response(503, { message: "still down" }));
    const { client } = makeClient({ maxRetries: 2 }, request);

    await expect(client.request({ method: "POST", path: "/v3/session/" })).rejects.toThrow(
      DiditServerError,
    );
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("honors an explicit retry:true override for mutating requests", async () => {
    const request = jest
      .fn()
      .mockResolvedValueOnce(response(503, { message: "unavailable" }))
      .mockResolvedValueOnce(response(200, { session_id: "s_1" }));
    const { client } = makeClient({ maxRetries: 2 }, request);

    const result = await client.request<{ session_id: string }>({
      method: "PATCH",
      path: "/v3/session/s_1/update-status/",
      retry: true,
    });

    expect(result.data).toEqual({ session_id: "s_1" });
    expect(request).toHaveBeenCalledTimes(2);
  });

  it("does not retry a 400 validation error even for GET requests", async () => {
    const request = jest.fn().mockResolvedValue(response(400, { message: "bad input" }));
    const { client } = makeClient({ maxRetries: 2 }, request);

    await expect(client.request({ method: "GET", path: "/v3/sessions/" })).rejects.toThrow(
      DiditValidationError,
    );
    expect(request).toHaveBeenCalledTimes(1);
  });
});
