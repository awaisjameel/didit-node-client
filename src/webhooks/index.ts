import type { ResolvedConfig } from "../config";
import type { WebhookHeaders, WebhookVerificationResult } from "../types/webhook";
import { verifyWebhookSignature, type VerifyWebhookOptions } from "./signature";

export { verifyWebhookSignature } from "./signature";
export type { VerifyWebhookOptions } from "./signature";
export { createRawBodyMiddleware } from "./middleware";
export type { RawBodyMiddlewareOptions } from "./middleware";

/**
 * Webhook helpers bound to the client's configured `webhookSecret`. Available at
 * `client.webhooks`.
 */
export class WebhooksResource {
  constructor(private readonly config: ResolvedConfig) {}

  /**
   * Verifies and parses an inbound webhook delivery using the client's configured
   * `webhookSecret` (override per-call via `options.secret`). See
   * {@link verifyWebhookSignature} for full behavior and the raw-body caveat.
   */
  constructEvent(
    rawBody: string | Buffer,
    headers: WebhookHeaders,
    options: VerifyWebhookOptions = {},
  ): WebhookVerificationResult {
    return verifyWebhookSignature(rawBody, headers, {
      secret: this.config.webhookSecret,
      ...options,
    });
  }
}
