import type {
  DocumentTypeCode,
  LanguageCode,
  ParsedAddress,
  SessionKind,
  SessionStatus,
} from "./common";

export type CallbackMethod = "initiator" | "completer" | "both";

export interface ContactDetails {
  email?: string;
  /** E.164 format, e.g. `"+14155552671"`. Ignored for KYB sessions. */
  phone?: string;
  send_notification_emails?: boolean;
  email_lang?: LanguageCode;
}

/** KYC-specific expected details. Ignored (with a warning from the API) on KYB sessions. */
export interface ExpectedKycDetails {
  first_name?: string;
  last_name?: string;
  /** `YYYY-MM-DD` */
  date_of_birth?: string;
  /** ISO 3166-1 alpha-3, e.g. `"USA"`. */
  nationality?: string;
  /** ISO 3166-1 alpha-3, e.g. `"USA"`. */
  id_country?: string;
  expected_document_types?: DocumentTypeCode[];
  address?: string;
  /** Required alongside `address` if `poa_country` is not set. ISO 3166-1 alpha-2. */
  country?: string;
  /** Required alongside `address` if `country` is not set. ISO 3166-1 alpha-2. */
  poa_country?: string;
  identification_number?: string;
  gender?: "M" | "F" | "X";
  ip_address?: string;
}

/** KYB-specific expected details. Ignored (with a warning from the API) on KYC sessions. */
export interface ExpectedKybDetails {
  /** Max 255 characters. */
  company_name?: string;
  /** ISO 3166-1 alpha-2, optionally with a subdivision, e.g. `"US-CA"`. */
  registry_country?: string;
  /** Max 100 characters. */
  registration_number?: string;
}

export type ExpectedDetails = ExpectedKycDetails & ExpectedKybDetails;

export interface CreateSessionRequest {
  /** UUID of the workflow to run. Determines whether the session is KYC or KYB. */
  workflow_id: string;
  /** Your stable identifier for the user/business. Enables session reuse and deduplication. */
  vendor_data?: string;
  /** Redirect URL after the user finishes verifying. Didit appends `verificationSessionId` and `status` query params. */
  callback?: string;
  /** Who gets redirected: the tab that started the session, the tab that finished it, or both. Default `"initiator"`. */
  callback_method?: CallbackMethod;
  /** Arbitrary JSON echoed back on the session and in webhooks. Never shown to the end user. */
  metadata?: Record<string, unknown>;
  /** UI language. Defaults to browser detection when omitted. */
  language?: LanguageCode;
  contact_details?: ContactDetails;
  expected_details?: ExpectedDetails;
  /**
   * Base64-encoded reference face image (max 2MB; jpeg/png/webp/tiff), or a raw `Buffer` —
   * the SDK base64-encodes a `Buffer` automatically. Required for Face Match workflows
   * unless `vendor_data` already has a stored reference face.
   */
  portrait_image?: string | Buffer;
  /** Sandbox-only: forces a deterministic outcome. Ignored outside sandbox applications. */
  sandbox_scenario?: string;
}

export interface Session {
  session_id: string;
  session_kind: SessionKind;
  session_number: number;
  /** Short-lived token embedded in `url`; not a bearer credential for the API itself. */
  session_token: string;
  /** Hosted verification URL — redirect or embed your end user here. */
  url: string;
  vendor_data?: string | null;
  metadata?: Record<string, unknown> | null;
  status: SessionStatus;
  workflow_id: string;
  /** The workflow version pinned to this session at creation time. */
  workflow_version: number;
  callback?: string | null;
}

export interface ListSessionsParams {
  /** `"user"` (KYC only, default), `"business"` (KYB only), or `"all"`. */
  session_kind?: SessionKind | "all";
  /** Max rows per page. Default 50, max 100. */
  limit?: number;
  /** Rows to skip for pagination. Default 0. */
  offset?: number;
  vendor_data?: string;
  /** One or more statuses; the SDK joins arrays into the comma-separated form the API expects. */
  status?: SessionStatus | SessionStatus[];
  workflow_id?: string | string[];
  /** ISO 3166-1 alpha-3 country code(s). */
  country?: string | string[];
  /** ISO 8601 date, inclusive. */
  date_from?: string;
  /** ISO 8601 date, inclusive. */
  date_to?: string;
  /** Smart match across UUID, session number, email, and names. */
  search?: string;
  /** KYC only. */
  didit_internal_id?: string;
  /** KYC only. */
  document_type?: DocumentTypeCode | DocumentTypeCode[];
  /** KYC only. */
  region?: string;
  /** KYC only. */
  session_type?: "API" | "HOSTED" | "MIGRATED";
  /** KYC only. */
  api_service?: string;
  /** KYC only. */
  screened_full_name?: string;
  /** KYC only. */
  is_kyc_to_be_reviewed?: boolean;
  /** KYC only. */
  status_initialized_as_in_review?: boolean;
}

export interface SessionSummary {
  session_id: string;
  session_kind: SessionKind;
  session_number: number;
  status: SessionStatus;
  vendor_data?: string | null;
  full_name?: string | null;
  company_name?: string | null;
  country?: string | null;
  document_type?: string | null;
  created_at: string;
  [key: string]: unknown;
}

export type UpdateStatusValue = "Approved" | "Declined" | "Resubmitted";

export interface NodeResubmission {
  node_id: string;
  feature: string;
}

export interface UpdateSessionStatusRequest {
  new_status: UpdateStatusValue;
  /** Free-text reason, stored in the session's audit trail. */
  comment?: string;
  /** Required when `new_status` is `"Resubmitted"`. Omit to let Didit auto-select resubmittable steps. */
  nodes_to_resubmit?: NodeResubmission[];
  /** Notify the end user of the status change by email. Default `false`. */
  send_email?: boolean;
  /** Required when `send_email` is `true`. */
  email_address?: string;
  email_language?: LanguageCode;
}

export interface UpdateSessionStatusResponse {
  session_id: string;
}

export interface UpdateKycDataRequest {
  document_type?: string;
  document_number?: string;
  personal_number?: string;
  date_of_birth?: string;
  date_of_issue?: string;
  expiration_date?: string;
  issuing_state?: string;
  first_name?: string;
  last_name?: string;
  gender?: "M" | "F" | "X";
  nationality?: string;
  marital_status?: string;
  place_of_birth?: string;
  address?: string;
  parsed_address?: ParsedAddress;
  extra_fields?: Record<string, unknown>;
  /** Targets a specific node in a multi-step workflow; omit for single-step workflows. */
  node_id?: string;
}

export interface UpdatePoaDataRequest {
  issuing_state?: string;
  document_type?: "utility_bill" | "bank_statement" | "lease_agreement" | (string & {});
  document_language?: string;
  issuer?: string;
  issue_date?: string;
  poa_address?: string;
  name_on_document?: string;
  poa_parsed_address?: ParsedAddress;
  extra_fields?: {
    bank_account_number?: string;
    bank_iban?: string;
    bank_sort_code?: string;
    bank_routing_number?: string;
    bank_swift_bic?: string;
    bank_branch_name?: string;
    bank_branch_address?: string;
    document_phone_number?: string;
    additional_names?: string[] | null;
    [key: string]: unknown;
  };
  node_id?: string;
}

export type RegistryStatus = "active" | "dissolved" | "struck_off" | "inactive";
export type CompanyVerificationStatus = "verified" | "failed" | "unknown";

export interface UpdateKybCompanyDataRequest {
  company_name?: string;
  registration_number?: string;
  /** ISO 3166-1 alpha-3. */
  country_code?: string;
  incorporation_date?: string;
  registration_date?: string;
  dissolution_date?: string;
  tax_number?: string;
  legal_address?: string;
  company_type?: string;
  registry_status?: RegistryStatus;
  verification_status?: CompanyVerificationStatus;
  alternative_names?: string;
  nature_of_business?: string;
  registered_capital?: string;
  website?: string;
  email?: string;
  phone?: string;
  legal_entity_identifier?: string;
  location_of_registration?: string;
  control_scheme?: string;
}
