/**
 * Error hierarchy for the Didit client.
 *
 * Every error thrown by this library is (or extends) {@link DiditError}, so a single
 * `catch (err) { if (err instanceof DiditError) ... }` is enough to catch everything the
 * SDK can throw. More specific subclasses let you branch on failure mode without parsing
 * message strings.
 */

/** Base class for every error raised by this SDK. */
export class DiditError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "DiditError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown when the client is misconfigured (missing API key, invalid base URL, etc). */
export class DiditConfigurationError extends DiditError {
  constructor(message: string) {
    super(message);
    this.name = "DiditConfigurationError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown for invalid input passed to an SDK method before any network call is made. */
export class DiditInvalidRequestError extends DiditError {
  constructor(message: string) {
    super(message);
    this.name = "DiditInvalidRequestError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown when a request could not reach Didit at all (DNS, TCP, TLS, timeout, abort). */
export class DiditConnectionError extends DiditError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "DiditConnectionError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface DiditAPIErrorDetails {
  /** HTTP status code returned by the API. */
  status: number;
  /** The request path that was called, e.g. "POST /v3/session/". */
  request: string;
  /** Parsed JSON error body, when the response was JSON. */
  body: unknown;
  /** Raw response headers. */
  headers: Record<string, string>;
  /** Didit's own error code / message field, when present in the body. */
  code?: string;
  requestId?: string;
  /** Populated only for 429 responses, from the rate-limit headers. */
  retryAfter?: number;
  limit?: number;
  remaining?: number;
  reset?: number;
}

/**
 * Thrown for non-2xx statuses or malformed successful responses. Subclassed per status code so
 * callers can branch with `instanceof` instead of checking `.status` directly.
 */
export class DiditAPIError extends DiditError {
  readonly status: number;
  readonly request: string;
  readonly body: unknown;
  readonly headers: Record<string, string>;
  readonly code?: string;
  readonly requestId?: string;

  constructor(message: string, details: DiditAPIErrorDetails) {
    super(message);
    this.name = "DiditAPIError";
    this.status = details.status;
    this.request = details.request;
    this.body = details.body;
    this.headers = details.headers;
    this.code = details.code;
    this.requestId = details.requestId;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** 400 — the request payload failed validation. */
export class DiditValidationError extends DiditAPIError {
  constructor(message: string, details: DiditAPIErrorDetails) {
    super(message, details);
    this.name = "DiditValidationError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** 401/403 — missing, invalid, or under-scoped API key. */
export class DiditAuthenticationError extends DiditAPIError {
  constructor(message: string, details: DiditAPIErrorDetails) {
    super(message, details);
    this.name = "DiditAuthenticationError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** 404 — the requested resource (session, import job, ...) does not exist. */
export class DiditNotFoundError extends DiditAPIError {
  constructor(message: string, details: DiditAPIErrorDetails) {
    super(message, details);
    this.name = "DiditNotFoundError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** 429 — rate limit exceeded. Carries the parsed rate-limit headers when available. */
export class DiditRateLimitError extends DiditAPIError {
  /** Seconds to wait before retrying, from the `Retry-After` header. */
  readonly retryAfter?: number;
  readonly limit?: number;
  readonly remaining?: number;
  readonly reset?: number;

  constructor(message: string, details: DiditAPIErrorDetails) {
    super(message, details);
    this.name = "DiditRateLimitError";
    this.retryAfter = details.retryAfter;
    this.limit = details.limit;
    this.remaining = details.remaining;
    this.reset = details.reset;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** 5xx — something went wrong on Didit's side. Safe to retry for idempotent requests. */
export class DiditServerError extends DiditAPIError {
  constructor(message: string, details: DiditAPIErrorDetails) {
    super(message, details);
    this.name = "DiditServerError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown by the webhook helpers when a payload's signature cannot be verified. */
export class DiditWebhookSignatureError extends DiditError {
  constructor(message: string) {
    super(message);
    this.name = "DiditWebhookSignatureError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Builds the appropriate {@link DiditAPIError} subclass for a given HTTP status code.
 * @internal
 */
export function createAPIError(
  status: number,
  message: string,
  details: DiditAPIErrorDetails,
): DiditAPIError {
  if (status === 400) return new DiditValidationError(message, details);
  if (status === 401 || status === 403) return new DiditAuthenticationError(message, details);
  if (status === 404) return new DiditNotFoundError(message, details);
  if (status === 429) return new DiditRateLimitError(message, details);
  if (status >= 500) return new DiditServerError(message, details);
  return new DiditAPIError(message, details);
}
