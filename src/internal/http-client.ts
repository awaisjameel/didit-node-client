import axios, { isAxiosError } from "axios";
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";
import type FormData from "form-data";
import type { ResolvedConfig } from "../config";
import {
  createAPIError,
  DiditAPIError,
  DiditConnectionError,
  DiditInvalidRequestError,
  DiditRateLimitError,
  DiditServerError,
} from "../errors";
import type { Logger } from "../logger";
import { computeBackoffDelayMs, sleep } from "./retry";
import { mergeSignals } from "./signal";

export type HttpMethod = "GET" | "HEAD" | "POST" | "PATCH" | "DELETE";

export interface RequestOptions {
  method: HttpMethod;
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  formData?: FormData;
  responseType?: "json" | "arraybuffer";
  headers?: Record<string, string>;
  /** Aborts the request. */
  signal?: AbortSignal;
  /** Overrides the client-level timeout for this call, in milliseconds. */
  timeout?: number;
  /**
   * Overrides the default retry policy for this call. By default only `GET`/`HEAD`
   * requests are retried automatically; set `true` to allow retries for a mutating
   * request you know is safe to repeat (e.g. it's naturally idempotent), or `false` to
   * disable retries entirely for this call.
   */
  retry?: boolean;
  /** Overrides the client-level `maxRetries` for this call. */
  maxRetries?: number;
}

export interface HttpResponse<T> {
  data: T;
  status: number;
  headers: Record<string, string>;
}

/** Thin, retrying, error-normalizing HTTP layer shared by every resource. @internal */
export class HttpClient {
  private readonly axios: AxiosInstance;

  constructor(
    private readonly config: ResolvedConfig,
    private readonly logger: Logger,
  ) {
    this.axios = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout,
      validateStatus: () => true,
      maxRedirects: 0,
    });
  }

  async request<T>(options: RequestOptions): Promise<HttpResponse<T>> {
    if (
      options.timeout !== undefined &&
      (!Number.isFinite(options.timeout) || options.timeout <= 0)
    ) {
      throw new DiditInvalidRequestError(
        "Request timeout must be a positive number of milliseconds.",
      );
    }
    const maxRetries = options.maxRetries ?? this.config.maxRetries;
    const retryAllowed = options.retry ?? (options.method === "GET" || options.method === "HEAD");

    let attempt = 0;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      try {
        return await this.attempt<T>(options);
      } catch (error) {
        const canRetry =
          !options.signal?.aborted && retryAllowed && attempt < maxRetries && isRetryable(error);
        if (!canRetry) throw error;

        const retryAfter =
          error instanceof DiditRateLimitError ? error.headers["retry-after"] : undefined;
        const delay = computeBackoffDelayMs(attempt, retryAfter);
        this.logger.debug("Retrying request", {
          method: options.method,
          path: options.path,
          attempt: attempt + 1,
          maxRetries,
          delayMs: delay,
        });
        try {
          await sleep(delay, options.signal);
        } catch (cause) {
          throw new DiditConnectionError(
            `Didit request aborted: ${options.method} ${options.path}`,
            { cause },
          );
        }
        attempt += 1;
      }
    }
  }

  private async attempt<T>(options: RequestOptions): Promise<HttpResponse<T>> {
    const requestLabel = `${options.method} ${options.path}`;
    const signal = mergeSignals(options.signal);

    const axiosConfig: AxiosRequestConfig = {
      method: options.method,
      url: options.path,
      params: options.query,
      data: options.formData ?? options.body,
      responseType: options.responseType === "arraybuffer" ? "arraybuffer" : "json",
      timeout: options.timeout ?? this.config.timeout,
      signal,
      headers: {
        "x-api-key": this.config.apiKey,
        "User-Agent": this.config.userAgent,
        Accept: "application/json",
        ...(options.formData
          ? options.formData.getHeaders()
          : { "Content-Type": "application/json" }),
        ...options.headers,
      },
    };

    this.logger.debug("Request", {
      method: options.method,
      path: options.path,
      query: options.query,
    });

    let response: AxiosResponse<unknown>;
    try {
      response = await this.axios.request(axiosConfig);
    } catch (error) {
      throw toConnectionError(error, requestLabel);
    }

    const headers = normalizeHeaders(response.headers as Record<string, unknown>);

    if (response.status >= 200 && response.status < 300) {
      const binary = options.responseType === "arraybuffer" ? toBuffer(response.data) : undefined;
      const valid =
        options.responseType === "arraybuffer"
          ? binary?.subarray(0, 4).toString("ascii") === "%PDF"
          : typeof response.data === "object" &&
            response.data !== null &&
            !Array.isArray(response.data);
      if (!valid) {
        throw new DiditAPIError(
          `Didit returned an invalid ${options.responseType === "arraybuffer" ? "PDF document" : "JSON object"}: ${requestLabel}`,
          {
            status: response.status,
            request: requestLabel,
            body: response.data,
            headers,
          },
        );
      }
      this.logger.debug("Response", {
        method: options.method,
        path: options.path,
        status: response.status,
      });
      return { data: response.data as T, status: response.status, headers };
    }

    throw buildAPIError(response, requestLabel, options.responseType === "arraybuffer");
  }
}

function isRetryable(error: unknown): boolean {
  return (
    error instanceof DiditConnectionError ||
    error instanceof DiditRateLimitError ||
    error instanceof DiditServerError
  );
}

function toConnectionError(error: unknown, request: string): DiditConnectionError {
  if (isAxiosError(error)) {
    if (error.code === "ERR_CANCELED" || error.name === "CanceledError") {
      return new DiditConnectionError(`Didit request aborted: ${request}`, { cause: error });
    }
    if (error.code === "ECONNABORTED" || error.message.toLowerCase().includes("timeout")) {
      return new DiditConnectionError(`Didit request timed out: ${request}`, { cause: error });
    }
    return new DiditConnectionError(`Didit request failed (${request}): ${error.message}`, {
      cause: error,
    });
  }
  const message = error instanceof Error ? error.message : String(error);
  return new DiditConnectionError(`Didit request failed (${request}): ${message}`, {
    cause: error,
  });
}

function buildAPIError(
  response: AxiosResponse<unknown>,
  request: string,
  wasArrayBuffer: boolean,
): Error {
  const headers = normalizeHeaders(response.headers as Record<string, unknown>);
  const body = wasArrayBuffer ? decodeArrayBufferBody(response.data) : response.data;
  const message =
    extractErrorMessage(body) ?? `Didit API request failed with status ${response.status}`;

  const rateLimit =
    response.status === 429
      ? {
          retryAfter: toNumber(headers["retry-after"]),
          limit: toNumber(headers["x-ratelimit-limit"]),
          remaining: toNumber(headers["x-ratelimit-remaining"]),
          reset: toNumber(headers["x-ratelimit-reset"]),
        }
      : {};

  return createAPIError(response.status, `Didit API error (${request}): ${message}`, {
    status: response.status,
    request,
    body,
    headers,
    code: extractErrorCode(body),
    requestId: headers["x-request-id"] ?? headers["x-didit-request-id"],
    ...rateLimit,
  });
}

function decodeArrayBufferBody(data: unknown): unknown {
  const bytes = toBuffer(data);
  if (!bytes) return data;
  try {
    const text = bytes.toString("utf8");
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function toBuffer(data: unknown): Buffer | undefined {
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (ArrayBuffer.isView(data)) return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  return undefined;
}

function extractErrorMessage(body: unknown): string | undefined {
  if (body === null || body === undefined) return undefined;
  if (typeof body === "string") return body;
  if (typeof body !== "object") return undefined;

  const record = body as Record<string, unknown>;
  const candidates = [record.message, record.detail, record.error, record.error_description];
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.length > 0) return candidate;
  }

  if (Array.isArray(record.errors) && record.errors.length > 0) {
    return record.errors
      .map((entry) => (typeof entry === "string" ? entry : JSON.stringify(entry)))
      .join("; ");
  }

  // Django REST Framework-style field errors: { "field_name": ["message"] }
  const fieldErrors = Object.entries(record)
    .filter(([, value]) => Array.isArray(value))
    .map(([field, value]) => `${field}: ${(value as unknown[]).join(", ")}`);
  if (fieldErrors.length > 0) return fieldErrors.join("; ");

  return undefined;
}

function extractErrorCode(body: unknown): string | undefined {
  if (body === null || typeof body !== "object") return undefined;
  const code = (body as Record<string, unknown>).code;
  return typeof code === "string" ? code : undefined;
}

function normalizeHeaders(headers: Record<string, unknown>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      result[key.toLowerCase()] = value
        .map((entry: unknown) =>
          typeof entry === "string" || typeof entry === "number" || typeof entry === "boolean"
            ? String(entry)
            : "",
        )
        .join(", ");
    } else if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean"
    ) {
      result[key.toLowerCase()] = String(value);
    }
  }
  return result;
}

function toNumber(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const num = Number(value);
  return Number.isFinite(num) ? num : undefined;
}
