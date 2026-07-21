import FormData from "form-data";
import { DiditInvalidRequestError } from "../errors";
import type { HttpClient } from "../internal/http-client";
import { appendImageField } from "../internal/image-input";
import type { RequestOptions } from "../types/common";
import type { IdVerificationRequest, IdVerificationResponse } from "../types/id-verification";

/**
 * The standalone ID Verification API — a single synchronous document check, without
 * spinning up a hosted session. Useful for server-side pipelines (e.g. verifying a document
 * already collected through your own UI) where you don't need Didit's hosted flow.
 */
export class IdVerificationResource {
  constructor(private readonly http: HttpClient) {}

  /**
   * Verifies a single identity document image (and optionally its back side), returning
   * extracted fields, authenticity warnings, and an `Approved`/`Declined` status.
   *
   * Rate limit: 300 requests/minute per API key.
   */
  async verify(
    request: IdVerificationRequest,
    options?: RequestOptions,
  ): Promise<IdVerificationResponse> {
    if (!request.front_image) {
      throw new DiditInvalidRequestError("`front_image` is required.");
    }

    const form = new FormData();
    appendImageField(form, "front_image", request.front_image);
    if (request.back_image) appendImageField(form, "back_image", request.back_image);

    appendField(form, "front_image_password", request.front_image_password);
    appendField(form, "back_image_password", request.back_image_password);
    appendField(form, "perform_document_liveness", request.perform_document_liveness);
    appendField(form, "minimum_age", request.minimum_age);
    appendField(form, "invalid_mrz_action", request.invalid_mrz_action);
    appendField(form, "inconsistent_data_action", request.inconsistent_data_action);
    appendField(
      form,
      "expiration_date_not_detected_action",
      request.expiration_date_not_detected_action,
    );
    appendField(form, "preferred_characters", request.preferred_characters);
    appendField(form, "save_api_request", request.save_api_request);
    appendField(form, "vendor_data", request.vendor_data);
    if (request.metadata) form.append("metadata", JSON.stringify(request.metadata));

    const { data } = await this.http.request<IdVerificationResponse>({
      method: "POST",
      path: "/v3/id-verification/",
      formData: form,
      signal: options?.signal,
      timeout: options?.timeoutMs ?? 30_000,
    });
    return data;
  }
}

function appendField(
  form: FormData,
  field: string,
  value: string | number | boolean | undefined,
): void {
  if (value === undefined) return;
  form.append(field, String(value));
}
