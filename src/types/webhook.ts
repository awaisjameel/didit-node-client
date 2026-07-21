import type { Environment, SessionKind, SessionStatus } from "./common";
import type { SessionDecision } from "./decision";

export type WebhookEventType =
  | "status.updated"
  | "data.updated"
  | "user.status.updated"
  | "user.data.updated"
  | "business.status.updated"
  | "business.data.updated"
  | "activity.created"
  | "transaction.created"
  | "transaction.status.updated"
  | "travel_rule.status.updated";

export type EntityStatus = "ACTIVE" | "FLAGGED" | "BLOCKED";

export interface WebhookEnvelope {
  event_id: string;
  webhook_type: WebhookEventType;
  /** Unix epoch seconds — when this delivery attempt was signed. */
  timestamp: number;
  /** Unix epoch seconds — when the underlying event originally occurred. */
  created_at: number;
  application_id: string;
  environment: Environment;
  status: string;
}

export interface ResubmitInfo {
  node_id: string;
  feature: string;
  [key: string]: unknown;
}

/** `status.updated` / `data.updated` — fired for both KYC and KYB sessions. */
export interface SessionWebhookEvent extends WebhookEnvelope {
  webhook_type: "status.updated" | "data.updated";
  status: SessionStatus;
  session_id: string;
  /** Present only for KYB sessions. */
  business_session_id?: string;
  session_kind?: SessionKind;
  workflow_id?: string;
  workflow_version?: number;
  vendor_data?: string | null;
  metadata?: Record<string, unknown> | null;
  /** The sandbox scenario armed on this session, if any. */
  sandbox_scenario?: string | null;
  /** Present when `status` is `Approved`, `Declined`, `In Review`, or `Abandoned`. */
  decision?: SessionDecision;
  /** Present when `status` is `Resubmitted`. */
  resubmit_info?: ResubmitInfo[];
}

/** `user.status.updated` / `user.data.updated`. */
export interface UserWebhookEvent extends WebhookEnvelope {
  webhook_type: "user.status.updated" | "user.data.updated";
  vendor_user_id: string;
  status: EntityStatus;
  previous_status?: EntityStatus;
  [key: string]: unknown;
}

/** `business.status.updated` / `business.data.updated`. */
export interface BusinessWebhookEvent extends WebhookEnvelope {
  webhook_type: "business.status.updated" | "business.data.updated";
  vendor_business_id: string;
  status: EntityStatus;
  previous_status?: EntityStatus;
  [key: string]: unknown;
}

/** `transaction.created` / `transaction.status.updated`. */
export interface TransactionWebhookEvent extends WebhookEnvelope {
  webhook_type: "transaction.created" | "transaction.status.updated";
  transaction_id: string;
  txn_id?: string;
  score?: number;
  severity?: string;
  amount?: number;
  currency?: string;
  direction?: string;
  [key: string]: unknown;
}

export type WebhookEvent =
  | SessionWebhookEvent
  | UserWebhookEvent
  | BusinessWebhookEvent
  | TransactionWebhookEvent
  | (WebhookEnvelope & Record<string, unknown>);

export type WebhookSignatureScheme = "v2" | "raw" | "simple";

export interface WebhookHeaders {
  "x-signature"?: string;
  "x-signature-v2"?: string;
  "x-signature-simple"?: string;
  "x-timestamp"?: string;
  "x-didit-test-webhook"?: string;
  [header: string]: string | string[] | undefined;
}

export interface WebhookVerificationResult<T = WebhookEvent> {
  event: T;
  /** Which signature scheme actually validated the request. */
  verifiedWith: WebhookSignatureScheme;
  /** `true` if Didit marked this as a console "Try Webhook" test delivery. */
  isTest: boolean;
}
