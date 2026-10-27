import type { Environment, SessionKind, SessionStatus } from "./common";
import type { SessionDecision } from "./decision";
import type { NodeResubmission } from "./session";

export type InvestigatorWebhookType = `investigator.${
  | "report.ready"
  | "decision.automated"
  | "decision.overridden"
  | "decision.contested"
  | "question.raised"
  | "automation.paused"
  | "rfi.answered"
  | "rfi.overdue"
  | "drift.detected"
  | "sla.breached"
  | "qa.failed"
  | "external.report.ready"}`;

export type AuthWebhookType = `auth.${
  | "signup"
  | "login"
  | "login_failed"
  | "password_reset_requested"
  | "password_reset_completed"
  | "mfa_changed"
  | "new_device"
  | "account_locked"}`;

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
  | "travel_rule.status.updated"
  | InvestigatorWebhookType
  | AuthWebhookType;

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
  status?: string;
}

export interface ResubmitInfo {
  nodes_to_resubmit: NodeResubmission[];
  reasons: Record<string, string>;
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
  resubmit_info?: ResubmitInfo;
  trigger?: "manual_review" | "manual_step_update" | "ongoing_monitoring";
  decided_by?: "investigator" | "human";
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
  status: "APPROVED" | "IN_REVIEW" | "DECLINED" | "AWAITING_USER";
  amount?: string;
  currency?: string;
  direction?: string;
  [key: string]: unknown;
}

/** Event families whose resource-specific data is available through the index signature. */
export interface OtherWebhookEvent extends WebhookEnvelope {
  webhook_type:
    "activity.created" | "travel_rule.status.updated" | InvestigatorWebhookType | AuthWebhookType;
  [key: string]: unknown;
}

export type WebhookEvent =
  | SessionWebhookEvent
  | UserWebhookEvent
  | BusinessWebhookEvent
  | TransactionWebhookEvent
  | OtherWebhookEvent;

export type WebhookSignatureScheme = "v2" | "raw";

export interface WebhookHeaders {
  "x-signature"?: string;
  "x-signature-v2"?: string;
  "x-signature-previous"?: string;
  "x-signature-v2-previous"?: string;
  "x-timestamp"?: string;
  "x-didit-test-webhook"?: string;
  [header: string]: string | string[] | undefined;
}

export interface WebhookVerificationResult<T = WebhookEvent> {
  event: T;
  /** Which signature scheme actually validated the request. */
  verifiedWith: WebhookSignatureScheme;
  /** Unsigned informational hint; never use this flag to bypass authorization. */
  isTest: boolean;
}
