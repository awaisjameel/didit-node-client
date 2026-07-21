export { DiditClient } from "./client";
export type { DiditClientConfig } from "./config";

export {
  DiditAPIError,
  DiditAuthenticationError,
  DiditConfigurationError,
  DiditConnectionError,
  DiditError,
  DiditInvalidRequestError,
  DiditNotFoundError,
  DiditRateLimitError,
  DiditServerError,
  DiditValidationError,
  DiditWebhookSignatureError,
} from "./errors";
export type { DiditAPIErrorDetails } from "./errors";

export { createRawBodyMiddleware, verifyWebhookSignature } from "./webhooks";
export type { RawBodyMiddlewareOptions, VerifyWebhookOptions } from "./webhooks";

export { SessionsResource } from "./resources/sessions";
export { IdVerificationResource } from "./resources/id-verification";
export { WebhooksResource } from "./webhooks";

export type { DiditLogFn } from "./logger";

export * from "./types";
