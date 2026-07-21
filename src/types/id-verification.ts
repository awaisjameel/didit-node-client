import type { ParsedAddress, Warning } from "./common";

/** Accepted image input across the SDK: a Buffer/stream you already have, or a file-like descriptor. */
export type ImageInput =
  | Buffer
  | NodeJS.ReadableStream
  | {
      data: Buffer | NodeJS.ReadableStream;
      filename?: string;
      contentType?: string;
    };

export type MrzAction = "DECLINE" | "NO_ACTION";
export type PreferredCharacters = "latin" | "non_latin";

export interface IdVerificationRequest {
  /** Front of the document. Formats: tiff, jpg, jpeg, png, webp, pdf. Max 10MB. */
  front_image: ImageInput;
  /** Back of the document, when applicable. */
  back_image?: ImageInput;
  /** Password for an encrypted `front_image` PDF. */
  front_image_password?: string;
  /** Password for an encrypted `back_image` PDF. */
  back_image_password?: string;
  /** Screens for presentation-fraud / spoofing on the document image. Default `false`. */
  perform_document_liveness?: boolean;
  /** 1-120. Currently not enforced by the API — reserved for future use. */
  minimum_age?: number;
  /** Default `"DECLINE"`. */
  invalid_mrz_action?: MrzAction;
  /** Default `"DECLINE"`. */
  inconsistent_data_action?: MrzAction;
  /** Default `"NO_ACTION"`. */
  expiration_date_not_detected_action?: MrzAction;
  /** Default `"latin"`. */
  preferred_characters?: PreferredCharacters;
  /** Persists this call as a retrievable session. Default `true`. */
  save_api_request?: boolean;
  vendor_data?: string;
  metadata?: Record<string, unknown>;
}

export interface IdVerificationDocumentResult {
  status: "Approved" | "Declined" | (string & {});
  document_type?: string;
  document_subtype?: string;
  document_number?: string;
  personal_number?: string;
  portrait_image?: string | null;
  front_image?: string | null;
  back_image?: string | null;
  date_of_birth?: string | null;
  age?: number | null;
  expiration_date?: string | null;
  /** ISO 3166-1 alpha-3. */
  issuing_state?: string | null;
  first_name?: string | null;
  last_name?: string | null;
  full_name?: string | null;
  gender?: "M" | "F" | null;
  address?: string | null;
  formatted_address?: string | null;
  parsed_address?: ParsedAddress | null;
  /** ISO 3166-1 alpha-3. */
  nationality?: string | null;
  mrz?: Record<string, unknown> | null;
  warnings: Warning[];
  barcodes?: unknown[];
  [key: string]: unknown;
}

export interface IdVerificationResponse {
  request_id: string;
  id_verification: IdVerificationDocumentResult;
  vendor_data?: string | null;
  metadata?: Record<string, unknown> | null;
  created_at: string;
}
