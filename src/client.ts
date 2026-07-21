import { resolveConfig, type DiditClientConfig } from "./config";
import { HttpClient } from "./internal/http-client";
import { Logger } from "./logger";
import { IdVerificationResource } from "./resources/id-verification";
import { SessionsResource } from "./resources/sessions";
import { WebhooksResource } from "./webhooks";

/**
 * Node.js client for the Didit Identity Verification API (v3).
 *
 * ```ts
 * import { DiditClient } from "didit-node-client";
 *
 * const didit = new DiditClient({ apiKey: process.env.DIDIT_API_KEY });
 *
 * const session = await didit.sessions.create({
 *   workflow_id: process.env.DIDIT_WORKFLOW_ID!,
 *   vendor_data: user.id,
 *   callback: "https://example.com/verification/callback",
 * });
 * // redirect the user to session.url, then verify results via webhook or
 * // await didit.sessions.retrieve(session.session_id)
 * ```
 *
 * All configuration can also come from environment variables (`DIDIT_API_KEY`,
 * `DIDIT_WEBHOOK_SECRET`, `DIDIT_BASE_URL`), so `new DiditClient()` with no arguments works
 * in most deployments.
 */
export class DiditClient {
  /** Create, retrieve, list, and manage verification sessions (KYC + KYB). */
  readonly sessions: SessionsResource;
  /** One-shot standalone document verification, without a hosted session. */
  readonly idVerification: IdVerificationResource;
  /** Verify and parse inbound webhook deliveries. */
  readonly webhooks: WebhooksResource;

  constructor(config: DiditClientConfig = {}) {
    const resolved = resolveConfig(config);
    const logger = new Logger(resolved.debug, resolved.logger);
    const http = new HttpClient(resolved, logger);

    this.sessions = new SessionsResource(http);
    this.idVerification = new IdVerificationResource(http);
    this.webhooks = new WebhooksResource(resolved);
  }
}
