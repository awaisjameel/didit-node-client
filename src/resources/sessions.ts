import { DiditInvalidRequestError } from "../errors";
import type { HttpClient } from "../internal/http-client";
import { normalizePortraitImage } from "../internal/image-input";
import { toQueryParams } from "../internal/query";
import type { PaginatedResponse, RequestOptions } from "../types/common";
import type { SessionDecision } from "../types/decision";
import type {
  CreateSessionRequest,
  ListSessionsParams,
  Session,
  SessionSummary,
  UpdateKybCompanyDataRequest,
  UpdateKycDataRequest,
  UpdatePoaDataRequest,
  UpdateSessionStatusRequest,
  UpdateSessionStatusResponse,
} from "../types/session";

function requireNonEmpty(value: string | undefined, name: string): asserts value is string {
  if (!value || value.trim().length === 0) {
    throw new DiditInvalidRequestError(`\`${name}\` is required.`);
  }
}

/**
 * The Sessions API — Didit's core hosted verification flow. Create a session, send the end
 * user to `session.url`, and either poll {@link SessionsResource.retrieve} or (recommended)
 * listen for the `status.updated` webhook to learn the outcome.
 */
export class SessionsResource {
  constructor(private readonly http: HttpClient) {}

  /**
   * Creates a new verification session (KYC or KYB, depending on `workflow_id`).
   *
   * If `vendor_data` matches an unfinished session (`Not Started`, `In Progress`,
   * `Resubmitted`, `Awaiting User`) on the current published version of the workflow, Didit
   * returns that existing session instead of creating a duplicate — `callback`/`metadata`
   * are refreshed on it. Finished sessions are never reused.
   */
  async create(params: CreateSessionRequest, options?: RequestOptions): Promise<Session> {
    requireNonEmpty(params.workflow_id, "workflow_id");

    const { data } = await this.http.request<Session>({
      method: "POST",
      path: "/v3/session/",
      body: {
        ...params,
        portrait_image: normalizePortraitImage(params.portrait_image),
      },
      signal: options?.signal,
      timeout: options?.timeoutMs,
    });
    return data;
  }

  /**
   * Retrieves the full decision for a session: status plus every feature result
   * (`id_verifications`, `aml_screenings`, `face_matches`, ...) that has run so far.
   *
   * Media URLs in the response are short-lived presigned links — fetch them promptly, or
   * call this again for fresh links.
   */
  async retrieve(sessionId: string, options?: RequestOptions): Promise<SessionDecision> {
    requireNonEmpty(sessionId, "sessionId");

    const { data } = await this.http.request<SessionDecision>({
      method: "GET",
      path: `/v3/session/${encodeURIComponent(sessionId)}/decision/`,
      signal: options?.signal,
      timeout: options?.timeoutMs,
    });
    return data;
  }

  /** Lists sessions with optional filters. Use {@link SessionsResource.listAll} to auto-paginate. */
  async list(
    params?: ListSessionsParams,
    options?: RequestOptions,
  ): Promise<PaginatedResponse<SessionSummary>> {
    if (params?.limit !== undefined && (!Number.isSafeInteger(params.limit) || params.limit < 1)) {
      throw new DiditInvalidRequestError("`limit` must be a positive safe integer.");
    }
    if (
      params?.offset !== undefined &&
      (!Number.isSafeInteger(params.offset) || params.offset < 0)
    ) {
      throw new DiditInvalidRequestError("`offset` must be a non-negative safe integer.");
    }
    const { data } = await this.http.request<PaginatedResponse<SessionSummary>>({
      method: "GET",
      path: "/v3/sessions/",
      query: toQueryParams(params),
      signal: options?.signal,
      timeout: options?.timeoutMs,
    });
    return data;
  }

  /**
   * Async-iterates every session matching `params`, transparently following pagination.
   *
   * @example
   * ```ts
   * for await (const session of client.sessions.listAll({ status: "In Review" })) {
   *   console.log(session.session_id);
   * }
   * ```
   */
  async *listAll(
    params?: Omit<ListSessionsParams, "offset">,
    options?: RequestOptions,
  ): AsyncGenerator<SessionSummary, void, void> {
    // Didit's merged endpoint derives next from KYC pagination only. Paginate
    // each kind separately so a short KYC result cannot truncate KYB results.
    if (params?.session_kind === "all") {
      yield* this.listAll({ ...params, session_kind: "user" }, options);
      yield* this.listAll({ ...params, session_kind: "business" }, options);
      return;
    }
    let offset = 0;
    const limit = params?.limit ?? 50;

    for (;;) {
      const page = await this.list({ ...params, limit, offset }, options);
      for (const item of page.results) yield item;

      if (page.results.length === 0) return;
      // KYB count is capped; a full page can still have more rows after next
      // becomes null. Never derive completion from the reported total count.
      if (!page.next && (params?.session_kind !== "business" || page.results.length < limit))
        return;
      offset += limit;
    }
  }

  /**
   * Approves, declines, or requests resubmission for a session. Fires the `status.updated`
   * webhook on success. The current status must already be terminal-ish (`Approved`,
   * `Declined`, `In Review`, `Kyc Expired`, `Abandoned`, or `Resubmitted`), and the request
   * is **not** idempotent — resending the same body returns `400`.
   */
  async updateStatus(
    sessionId: string,
    payload: UpdateSessionStatusRequest,
    options?: RequestOptions,
  ): Promise<UpdateSessionStatusResponse> {
    requireNonEmpty(sessionId, "sessionId");
    if (payload.send_email && !payload.email_address) {
      throw new DiditInvalidRequestError("`email_address` is required when `send_email` is true.");
    }

    const { data } = await this.http.request<UpdateSessionStatusResponse>({
      method: "PATCH",
      path: `/v3/session/${encodeURIComponent(sessionId)}/update-status/`,
      body: payload,
      signal: options?.signal,
      timeout: options?.timeoutMs,
    });
    return data;
  }

  /** Corrects OCR-extracted KYC identity fields on a completed session. Fires `data.updated`. */
  async updateData(
    sessionId: string,
    payload: UpdateKycDataRequest,
    options?: RequestOptions,
  ): Promise<Record<string, unknown>> {
    requireNonEmpty(sessionId, "sessionId");

    const { data } = await this.http.request<Record<string, unknown>>({
      method: "PATCH",
      path: `/v3/session/${encodeURIComponent(sessionId)}/update-data/`,
      body: payload,
      signal: options?.signal,
      timeout: options?.timeoutMs,
    });
    return data;
  }

  /** Corrects OCR-extracted Proof of Address fields on a completed session. Fires `data.updated`. */
  async updatePoaData(
    sessionId: string,
    payload: UpdatePoaDataRequest,
    options?: RequestOptions,
  ): Promise<Record<string, unknown>> {
    requireNonEmpty(sessionId, "sessionId");

    const { data } = await this.http.request<Record<string, unknown>>({
      method: "PATCH",
      path: `/v3/session/${encodeURIComponent(sessionId)}/update-poa-data/`,
      body: payload,
      signal: options?.signal,
      timeout: options?.timeoutMs,
    });
    return data;
  }

  /** Corrects registry-extracted KYB company fields on a business session. Fires `data.updated`. */
  async updateKybCompanyData(
    sessionId: string,
    companyUuid: string,
    payload: UpdateKybCompanyDataRequest,
    options?: RequestOptions,
  ): Promise<Record<string, unknown>> {
    requireNonEmpty(sessionId, "sessionId");
    requireNonEmpty(companyUuid, "companyUuid");

    const { data } = await this.http.request<Record<string, unknown>>({
      method: "PATCH",
      path: `/v3/session/${encodeURIComponent(sessionId)}/kyb/${encodeURIComponent(companyUuid)}/update-data/`,
      body: payload,
      signal: options?.signal,
      timeout: options?.timeoutMs,
    });
    return data;
  }

  /**
   * Renders a compliance-ready PDF report for a session. Eligible statuses: KYC —
   * `Approved`, `Declined`, `In Review`, `Kyc Expired`; KYB — `Approved`, `Declined`,
   * `In Review`. Rate-limited to 50 requests/minute per credential; each call re-renders
   * from current data (no caching).
   */
  async generatePdf(sessionId: string, options?: RequestOptions): Promise<Buffer> {
    requireNonEmpty(sessionId, "sessionId");

    const { data } = await this.http.request<ArrayBuffer>({
      method: "GET",
      path: `/v3/session/${encodeURIComponent(sessionId)}/generate-pdf/`,
      responseType: "arraybuffer",
      headers: { Accept: "application/pdf" },
      signal: options?.signal,
      timeout: options?.timeoutMs ?? 60_000,
    });
    return Buffer.from(data);
  }
}
