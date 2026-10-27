import type {
  DecisionFeature,
  Environment,
  ParsedAddress,
  Review,
  SessionKind,
  SessionStatus,
  Warning,
} from "./common";
import type { ContactDetails, ExpectedDetails } from "./session";

/**
 * Every feature result array below carries `node_id`, correlating the result to the node
 * in the workflow graph that produced it (relevant for multi-step / branching workflows).
 * All feature arrays are `undefined` until that feature actually runs for the session.
 *
 * Fields not yet covered by Didit's public schema still surface via the index signature on
 * each interface, so the SDK never drops data your account has access to.
 */
interface DecisionItemBase {
  node_id?: string | null;
  status: string;
  warnings?: Warning[];
  [key: string]: unknown;
}

export interface MatchResult {
  matched: boolean;
  field?: string;
  score?: number;
  [key: string]: unknown;
}

export interface IdVerificationResult extends DecisionItemBase {
  document_type?: string;
  document_subtype?: string;
  document_number?: string;
  personal_number?: string;
  portrait_image?: string | null;
  front_image?: string | null;
  front_video?: string | null;
  back_image?: string | null;
  back_video?: string | null;
  full_front_image?: string | null;
  full_back_image?: string | null;
  extra_files?: string[];
  date_of_birth?: string | null;
  age?: number | null;
  expiration_date?: string | null;
  date_of_issue?: string | null;
  /** ISO 3166-1 alpha-3. */
  issuing_state?: string | null;
  issuing_state_name?: string | null;
  first_name?: string | null;
  last_name?: string | null;
  full_name?: string | null;
  gender?: string | null;
  address?: string | null;
  formatted_address?: string | null;
  parsed_address?: ParsedAddress | null;
  place_of_birth?: string | null;
  marital_status?: string | null;
  /** ISO 3166-1 alpha-3. */
  nationality?: string | null;
  extra_fields?: Record<string, unknown> | null;
  mrz?: Record<string, unknown> | null;
  matches?: MatchResult[];
}

export interface NfcVerificationResult extends DecisionItemBase {
  portrait_image?: string | null;
  signature_image?: string | null;
  chip_data?: Record<string, unknown> | null;
  authenticity?: Record<string, unknown> | null;
  certificate_summary?: Record<string, unknown> | null;
}

export type LivenessMethod = "active" | "passive" | (string & {});

export interface LivenessCheckResult extends DecisionItemBase {
  method?: LivenessMethod;
  /** 0-100. */
  score?: number | null;
  reference_image?: string | null;
  video_url?: string | null;
  age_estimation?: number | null;
  face_quality?: number | null;
  face_luminance?: number | null;
  matches?: MatchResult[];
}

export interface FaceMatchResult extends DecisionItemBase {
  /** 0-100 similarity score. */
  score?: number | null;
  source_image_session_id?: string | null;
  source_image?: string | null;
  target_image?: string | null;
}

export interface AmlHit {
  id: string;
  match: boolean;
  /** 0-1 similarity score for this specific hit. */
  score: number;
  target: boolean;
  caption: string;
  datasets: string[];
  features?: Record<string, number>;
  last_seen?: string | null;
  first_seen?: string | null;
  last_change?: string | null;
  properties?: {
    name?: string[];
    alias?: string[];
    notes?: string[];
    gender?: string[];
    topics?: string[];
    position?: string[];
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface AmlScreeningResult extends DecisionItemBase {
  total_hits?: number;
  entity_type?: string;
  /** 0-100 score of the highest-scoring hit. */
  score?: number | null;
  hits?: AmlHit[];
  screened_data?: Record<string, unknown> | null;
  is_ongoing_monitoring_enabled?: boolean;
  next_ongoing_monitoring_bill_date?: string | null;
}

export interface PoaVerificationResult extends DecisionItemBase {
  /** ISO 3166-1 alpha-3. */
  issuing_state?: string | null;
  document_type?: string | null;
  document_subtype?: string | null;
  issuer?: string | null;
  issue_date?: string | null;
  poa_address?: string | null;
  name_on_document?: string | null;
  poa_parsed_address?: ParsedAddress | null;
}

export interface PhoneVerificationResult extends DecisionItemBase {
  phone_number?: string | null;
  carrier?: string | null;
  verification_method?: string | null;
  matches?: MatchResult[];
}

export interface EmailVerificationResult extends DecisionItemBase {
  email?: string | null;
  is_breached?: boolean | null;
  matches?: MatchResult[];
}

export interface IpAnalysisResult extends DecisionItemBase {
  device_brand?: string | null;
  device_model?: string | null;
  browser_family?: string | null;
  os_family?: string | null;
  platform?: string | null;
  ip_country?: string | null;
  ip_country_code?: string | null;
  ip_state?: string | null;
  ip_city?: string | null;
  ip_address?: string | null;
  isp?: string | null;
  organization?: string | null;
  is_vpn_or_tor?: boolean;
  is_data_center?: boolean;
  time_zone?: string | null;
  time_zone_offset?: string | null;
  document_location?: { latitude: number; longitude: number } | null;
  ip_location?: { latitude: number; longitude: number } | null;
  distance_from_document_to_ip_km?: { distance: number; direction: string } | null;
}

export interface DatabaseValidationResult extends DecisionItemBase {
  database?: string;
  matched?: boolean;
}

export interface DocumentAiDocumentResult extends DecisionItemBase {
  document_type?: string;
  extracted_fields?: Record<string, unknown>;
}

export interface QuestionnaireResponse {
  node_id?: string | null;
  question: string;
  answer: unknown;
  [key: string]: unknown;
}

// --- KYB-only feature results -------------------------------------------------------------

export type CompanyRegistryStatus =
  "active" | "dissolved" | "struck_off" | "inactive" | (string & {});

export interface RegistryCheckResult extends DecisionItemBase {
  company_uuid?: string;
  company_name?: string | null;
  registration_number?: string | null;
  /** ISO 3166-1 alpha-3. */
  country_code?: string | null;
  registry_status?: CompanyRegistryStatus | null;
  incorporation_date?: string | null;
  legal_address?: string | null;
  company_type?: string | null;
}

export interface BusinessDocumentVerificationResult extends DecisionItemBase {
  company_uuid?: string;
  document_type?: string | null;
}

export interface KeyPersonCheckResult extends DecisionItemBase {
  company_uuid?: string;
  full_name?: string | null;
  role?: string | null;
  /** Ultimate Beneficial Owner. */
  is_ubo?: boolean;
  ownership_percentage?: number | null;
}

/**
 * Full verification result for a session, as returned by
 * `GET /v3/session/{sessionId}/decision/` and embedded in `status.updated` webhooks once the
 * session reaches a terminal-ish status (`Approved`, `Declined`, `In Review`, `Abandoned`).
 *
 * Every `*_verifications` / `*_checks` / `*_screenings` array is `undefined` until that
 * feature actually ran on the session's workflow. Media URLs (images/video) are short-lived
 * presigned links — fetch them promptly, or re-request the decision for fresh links.
 */
export interface SessionDecision {
  session_id: string;
  session_kind: SessionKind;
  session_number: number | null;
  session_url: string | null;
  status: SessionStatus;
  environment: Environment;
  workflow_id: string | null;
  workflow_version?: number;
  /** Feature identifiers that actually executed for this session. */
  features?: DecisionFeature[];
  vendor_data?: string | null;
  metadata?: Record<string, unknown> | null;
  expected_details?: ExpectedDetails | null;
  contact_details?: ContactDetails | null;
  callback?: string | null;

  id_verifications?: IdVerificationResult[] | null;
  nfc_verifications?: NfcVerificationResult[] | null;
  liveness_checks?: LivenessCheckResult[] | null;
  face_matches?: FaceMatchResult[] | null;
  phone_verifications?: PhoneVerificationResult[] | null;
  email_verifications?: EmailVerificationResult[] | null;
  poa_verifications?: PoaVerificationResult[] | null;
  aml_screenings?: AmlScreeningResult[] | null;
  ip_analyses?: IpAnalysisResult[] | null;
  database_validations?: DatabaseValidationResult[] | null;
  document_ai_documents?: DocumentAiDocumentResult[] | null;
  questionnaire_responses?: QuestionnaireResponse[] | null;

  /** KYB only. */
  registry_checks?: RegistryCheckResult[] | null;
  /** KYB only. */
  document_verifications?: BusinessDocumentVerificationResult[] | null;
  /** KYB only. */
  key_people_checks?: KeyPersonCheckResult[] | null;

  warnings?: Warning[];
  reviews?: Review[];
  extra_images?: string[];
  created_at: string;

  [key: string]: unknown;
}
