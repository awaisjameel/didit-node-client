import { DiditConfigurationError } from "./errors";
import type { DiditLogFn } from "./logger";
import { SDK_VERSION } from "./version";

export interface DiditClientConfig {
  /**
   * Your Didit API key (Business Console → API keys). Sent as the `x-api-key` header on
   * every request. Falls back to the `DIDIT_API_KEY` environment variable.
   *
   * Keep this on your backend only — it must never be shipped to a browser or mobile app.
   */
  apiKey?: string;

  /**
   * Shared secret used to verify `x-signature*` headers on incoming webhooks. Falls back to
   * the `DIDIT_WEBHOOK_SECRET` environment variable. Only required if you use
   * {@link DiditClient.webhooks}.
   */
  webhookSecret?: string;

  /**
   * Base URL for the Verification API. Falls back to `DIDIT_BASE_URL`, then
   * `https://verification.didit.me`. Override for testing against a mock server.
   */
  baseUrl?: string;

  /** Per-request timeout in milliseconds. Default `15000`. */
  timeout?: number;

  /**
   * Maximum number of automatic retries for safe (`GET`) requests that fail with a network
   * error, a `429`, or a `5xx` response. Uses exponential backoff with jitter and honors the
   * `Retry-After` header. Default `2`. Set to `0` to disable.
   */
  maxRetries?: number;

  /** Enables verbose debug logging (secrets are always redacted). Default `false`. */
  debug?: boolean;

  /** Custom sink for debug logs. Defaults to `console.log`. Ignored unless `debug` is true. */
  logger?: DiditLogFn;

  /** Extra string appended to the `User-Agent` header, e.g. `"my-app/1.2.0"`. */
  appInfo?: string;
}

export interface ResolvedConfig {
  apiKey: string;
  webhookSecret?: string;
  baseUrl: string;
  timeout: number;
  maxRetries: number;
  debug: boolean;
  logger?: DiditLogFn;
  userAgent: string;
}

const DEFAULT_BASE_URL = "https://verification.didit.me";
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_RETRIES = 2;

export function resolveConfig(config: DiditClientConfig): ResolvedConfig {
  const apiKey = config.apiKey ?? process.env.DIDIT_API_KEY;
  const baseUrl = (config.baseUrl ?? process.env.DIDIT_BASE_URL ?? DEFAULT_BASE_URL).replace(
    /\/+$/,
    "",
  );
  const webhookSecret = config.webhookSecret ?? process.env.DIDIT_WEBHOOK_SECRET;

  if (!apiKey) {
    throw new DiditConfigurationError(
      "A Didit API key is required. Pass `apiKey` to `new DiditClient({ apiKey })` or set the " +
        "DIDIT_API_KEY environment variable. Find your key in the Didit Business Console under " +
        "Settings → API Keys.",
    );
  }

  if (!isValidUrl(baseUrl)) {
    throw new DiditConfigurationError(
      `\`baseUrl\` must be a valid absolute URL, received: "${baseUrl}"`,
    );
  }

  const timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new DiditConfigurationError("`timeout` must be a positive number of milliseconds.");
  }

  const maxRetries = config.maxRetries ?? DEFAULT_MAX_RETRIES;
  if (!Number.isInteger(maxRetries) || maxRetries < 0) {
    throw new DiditConfigurationError("`maxRetries` must be a non-negative integer.");
  }

  const userAgent = `didit-node-client/${SDK_VERSION} node/${process.version}${
    config.appInfo ? ` ${config.appInfo}` : ""
  }`;

  return {
    apiKey,
    webhookSecret,
    baseUrl,
    timeout,
    maxRetries,
    debug: config.debug ?? false,
    logger: config.logger,
    userAgent,
  };
}

function isValidUrl(value: string): boolean {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}
