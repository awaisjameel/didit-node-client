/** Lifecycle status of a verification session. */
export type SessionStatus =
  | "Not Started"
  | "In Progress"
  | "Awaiting User"
  | "In Review"
  | "Approved"
  | "Declined"
  | "Resubmitted"
  | "Expired"
  | "Kyc Expired"
  | "Abandoned";

/** Discriminates a KYC (individual) session from a KYB (business) session. */
export type SessionKind = "user" | "business";

export type Environment = "live" | "sandbox";

/** ISO 639-1 two-letter language code, e.g. `"en"`, `"es"`, `"fr"`. */
export type LanguageCode = string;

/** Feature identifiers as they appear in `decision.features`. */
export type DecisionFeature =
  | "ID_VERIFICATION"
  | "NFC"
  | "LIVENESS"
  | "FACE_MATCH"
  | "POA"
  | "PHONE"
  | "EMAIL"
  | "AML"
  | "IP_ANALYSIS"
  | "DATABASE_VALIDATION"
  | "QUESTIONNAIRE"
  | (string & {});

/** ICAO document-type codes accepted by `expected_document_types`. */
export type DocumentTypeCode =
  | "P" // Passport
  | "ID" // National ID card
  | "DL" // Driver's license
  | "RP" // Residence permit
  | "HIC" // Health insurance card
  | "TC" // Travel card
  | "SSC"; // Social security card

export type RiskLogType = "error" | "warning" | "information";

/** A non-fatal issue surfaced by a verification feature (e.g. AML possible match). */
export interface Warning {
  feature: DecisionFeature;
  risk: string;
  additional_data?: Record<string, unknown> | null;
  log_type: RiskLogType;
  short_description: string;
  long_description: string;
  node_id?: string | null;
}

export interface ParsedAddress {
  address_type?: string | null;
  city?: string | null;
  region?: string | null;
  street_1?: string | null;
  street_2?: string | null;
  postal_code?: string | null;
  /** ISO 3166-1 alpha-2 country code. */
  country?: string | null;
}

/** A compliance reviewer's status change entry on a session. */
export interface Review {
  user: string;
  new_status: string;
  comment?: string | null;
  created_at: string;
}

/** Generic cursor-style pagination envelope used by list endpoints. */
export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

/** Options accepted by every SDK method that issues a network request. */
export interface RequestOptions {
  /** Aborts the request (e.g. `AbortController#signal`). */
  signal?: AbortSignal;
  /** Overrides the client-level timeout for this call, in milliseconds. */
  timeoutMs?: number;
}
