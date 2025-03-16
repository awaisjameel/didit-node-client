import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";
import crypto from "crypto";
import { Buffer } from "buffer";

interface DiDiTConfig {
  clientId?: string;
  clientSecret?: string;
  baseUrl?: string;
  authUrl?: string;
  webhookSecret?: string;
  tokenExpiryBuffer?: number;
  timeout?: number;
  debug?: boolean;
}

interface TokenCache {
  access_token: string | null;
  expires_at: number | null;
}

interface AuthResponse {
  access_token: string;
  expires_in: number;
  iss: string;
  iat: number;
  sub: string;
  client_id: string;
  organization_id: string;
  exp: number;
}

interface SessionResponse {
  session_id: string;
  session_number: number;
  session_token: string;
  vendor_data?: any;
  status: string;
  callback: string;
  url: string;
  features: string;
}

interface SessionDecision {
  session_id: string;
  session_number: number;
  session_url: string;
  status: string;
  vendor_data?: any;
  callback: string;
  features: string;
  kyc?: {
    status: string;
    ocr_status: string;
    epassport_status: string;
    document_type: string;
    document_number: string;
    personal_number?: string;
    portrait_image?: string;
    front_image?: string;
    front_video?: string;
    back_image?: string;
    back_video?: string;
    full_front_image?: string;
    full_back_image?: string;
    date_of_birth?: string;
    expiration_date?: string;
    date_of_issue?: string;
    issuing_state?: string;
    issuing_state_name?: string;
    first_name?: string;
    last_name?: string;
    full_name?: string;
    gender?: string;
    address?: string;
    formatted_address?: string;
    is_nfc_verified?: boolean;
    parsed_address?: any;
    place_of_birth?: string;
    marital_status?: string;
    nationality?: string;
    created_at: string;
  };
  aml?: {
    status: string;
    total_hits: number;
    score: number;
    hits: Array<{
      id: string;
      match: boolean;
      score: number;
      target: boolean;
      caption: string;
      datasets: string[];
      features: Record<string, number>;
      last_seen: string;
      first_seen: string;
      properties: {
        name?: string[];
        alias?: string[];
        notes?: string[];
        gender?: string[];
        topics?: string[];
        position?: string[];
        [key: string]: any;
      };
      last_change: string;
    }>;
  };
  face?: {
    status: string;
    face_match_status: string;
    liveness_status: string;
    face_match_similarity: number;
    liveness_confidence: number;
    source_image?: string;
    target_image?: string;
    video_url?: string;
    age_estimation?: number;
    gender_estimation?: {
      male: number;
      female: number;
    };
  };
  location?: {
    status: string;
    device_brand?: string;
    device_model?: string;
    browser_family?: string;
    os_family?: string;
    platform?: string;
    ip_country?: string;
    ip_country_code?: string;
    ip_state?: string;
    ip_city?: string;
    latitude?: number;
    longitude?: number;
    ip_address?: string;
    isp?: string;
    organization?: string;
    is_vpn_or_tor: boolean;
    is_data_center: boolean;
    time_zone?: string;
    time_zone_offset?: string;
    document_location?: {
      latitude: number;
      longitude: number;
    };
    ip_location?: {
      latitude: number;
      longitude: number;
    };
    distance_from_document_to_ip_km?: {
      distance: number;
      direction: string;
    };
  };
  warnings?: Array<{
    feature: string;
    risk: string;
    additional_data?: any;
    log_type: string;
    short_description: string;
    long_description: string;
  }>;
  reviews?: Array<{
    user: string;
    new_status: string;
    comment: string;
    created_at: string;
  }>;
  extra_images?: string[];
  created_at: string;
}

interface SessionOptions {
  callback: string;
  features?: string;
  vendor_data?: Record<string, any>;
}

interface WebhookHeaders {
  "x-signature": string;
  "x-timestamp": string;
  [key: string]: string;
}

interface WebhookEvent {
  session_id: string;
  status: string;
  created_at: number;
  timestamp: number;
  vendor_data?: any;
  decision?: SessionDecision;
}

interface ApiRequestOptions extends AxiosRequestConfig {
  context?: string;
}

/**
 * DiDiTClient - A TypeScript client library for the DiDiT verification API
 *
 * Features:
 * - Authentication token management with auto-refresh
 * - Session management (create, retrieve, update status)
 * - PDF report generation
 * - Webhook signature verification and processing
 * - Comprehensive error handling and debug logging
 */
class DiDiTClient {
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly baseUrl: string;
  private readonly authUrl: string;
  private readonly webhookSecret?: string;
  private readonly tokenExpiryBuffer: number;
  private readonly timeout: number;
  private readonly debug: boolean;
  private tokenCache: TokenCache;

  constructor(config: DiDiTConfig = {}) {
    // Required configuration
    this.clientId = config.clientId || process.env.DIDIT_CLIENT_ID!;
    this.clientSecret = config.clientSecret || process.env.DIDIT_CLIENT_SECRET!;
    this.baseUrl =
      config.baseUrl ||
      process.env.DIDIT_BASE_URL ||
      "https://verification.didit.me";
    this.authUrl =
      config.authUrl || process.env.DIDIT_AUTH_URL || "https://apx.didit.me";
    this.webhookSecret =
      config.webhookSecret || process.env.DIDIT_WEBHOOK_SECRET;

    // Optional configuration
    this.tokenExpiryBuffer = config.tokenExpiryBuffer || 300; // 5 minutes buffer before token expiry
    this.timeout = config.timeout || 10000; // 10 seconds
    this.debug = config.debug || false;

    // Token cache
    this.tokenCache = {
      access_token: null,
      expires_at: null,
    };

    // Validate required configuration
    this.validateConfig();
  }

  /**
   * Validates that required configuration is present
   * @private
   */
  private validateConfig(): void {
    if (!this.clientId) throw new Error("DIDIT_CLIENT_ID is required");
    if (!this.clientSecret) throw new Error("DIDIT_CLIENT_SECRET is required");
    if (!this.baseUrl) throw new Error("DIDIT_BASE_URL is required");
    if (!this.authUrl) throw new Error("DIDIT_AUTH_URL is required");
  }

  /**
   * Creates an instance of axios with common configuration
   * @private
   * @param {Object} options - Additional axios options
   * @returns {Object} Axios instance
   */
  private createRequestInstance(
    options: AxiosRequestConfig = {}
  ): AxiosInstance {
    return axios.create({
      timeout: this.timeout,
      ...options,
    });
  }

  /**
   * Logs debug messages if debug mode is enabled
   * @private
   * @param {string} message - Debug message
   * @param {Object} data - Optional data to log
   */
  private log(message: string, data: any = null): void {
    if (this.debug) {
      console.log(`[DiDiT] ${message}`, data ? data : "");
    }
  }

  /**
   * Handles error reporting and formatting
   * @private
   * @param {Error} error - Error object
   * @param {string} context - Context where the error occurred
   * @returns {Error} Formatted error
   */
  private handleError(error: Error, context: string): Error {
    const errorMessage = `DiDiT ${context} error: ${error.message}`;

    // Extract API error details if available
    if ((error as any).response && (error as any).response.data) {
      this.log("API Error Details:", (error as any).response.data);
    }

    // Create new error with more context
    const formattedError = new Error(errorMessage);
    (formattedError as any).originalError = error;
    (formattedError as any).context = context;
    (formattedError as any).response = (error as any).response;

    return formattedError;
  }

  /**
   * Gets an access token, either from cache or by requesting a new one
   * @returns Promise resolving to the access token string
   * @throws Error if authentication fails
   */
  public async getAccessToken(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);

    // Return cached token if still valid
    if (
      this.tokenCache.access_token &&
      this.tokenCache.expires_at! > now + this.tokenExpiryBuffer
    ) {
      this.log("Using cached access token");
      return this.tokenCache.access_token!;
    }

    this.log("Fetching new access token");

    try {
      const url = `${this.authUrl}/auth/v2/token/`;
      const encodedCredentials = Buffer.from(
        `${this.clientId}:${this.clientSecret}`
      ).toString("base64");
      const params = new URLSearchParams();
      params.append("grant_type", "client_credentials");

      const response: AxiosResponse<AuthResponse> =
        await this.createRequestInstance().post(url, params, {
          headers: {
            Authorization: `Basic ${encodedCredentials}`,
            "Content-Type": "application/x-www-form-urlencoded",
          },
        });

      if (!response.data || !response.data.access_token) {
        throw new Error("Invalid response from auth server");
      }

      // Cache the token with expiry
      this.tokenCache = {
        access_token: response.data.access_token,
        expires_at: now + (response.data.expires_in || 3600), // Default 1 hour if not specified
      };

      return `${this.tokenCache.access_token}`;
    } catch (error) {
      throw this.handleError(error as Error, "authentication");
    }
  }

  /**
   * Makes an authenticated API request to DiDiT
   * @private
   * @param {Object} options - Request options
   * @returns {Promise<Object>} API response
   */
  private async makeAuthenticatedRequest<T>(
    options: ApiRequestOptions & { context: string }
  ): Promise<T> {
    try {
      const accessToken = await this.getAccessToken();
      const abortController = new AbortController();

      const requestOptions: AxiosRequestConfig = {
        ...options,
        headers: {
          ...options.headers,
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        signal: abortController.signal,
      };

      // Add timeout handling
      const timeoutId = setTimeout(() => {
        abortController.abort();
      }, this.timeout);

      try {
        const response: AxiosResponse<T> =
          await this.createRequestInstance().request(requestOptions);
        return response.data;
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw this.handleError(new Error("Request timeout"), options.context);
      }
      throw this.handleError(error as Error, options.context || "API request");
    }
  }

  /**
   * Creates a new verification session
   * @param callback_url - The URL to redirect to after verification
   * @param vendor_data - Optional custom data to associate with the session
   * @param options - Additional session configuration options
   * @returns Promise resolving to the created session data
   * @throws Error if session creation fails
   */
  public async createSession(
    callback_url: string,
    vendor_data?: Record<string, any>,
    options: Partial<SessionOptions> = {}
  ): Promise<SessionResponse> {
    if (!callback_url) {
      throw new Error("callback_url is required");
    }

    const data: SessionOptions = {
      callback: callback_url,
      ...options,
    };

    if (vendor_data) {
      data.vendor_data = vendor_data;
    }

    return this.makeAuthenticatedRequest({
      url: `${this.baseUrl}/v1/session/`,
      method: "POST",
      data,
      context: "session creation",
    });
  }

  /**
   * Generates a PDF report for a session
   * @param sessionId - The ID of the session
   * @returns Promise resolving to the PDF data as a Buffer
   * @throws Error if PDF generation fails
   */
  public async generateSessionPDF(sessionId: string): Promise<Buffer> {
    if (!sessionId) {
      throw new Error("sessionId is required");
    }

    const response = await this.makeAuthenticatedRequest<ArrayBuffer>({
      url: `${this.baseUrl}/v1/session/${sessionId}/generate-pdf/`,
      method: "GET",
      responseType: "arraybuffer",
      headers: {
        Accept: "application/pdf",
      },
      context: "PDF generation",
    });

    return Buffer.from(new Uint8Array(response));
  }

  /**
   * Updates the status of a session
   * @param sessionId - The ID of the session
   * @param newStatus - The new status ('Approved' or 'Declined')
   * @param comment - Optional comment for the status update
   * @returns Promise resolving to the updated session data
   * @throws Error if status update fails
   */
  public async updateSessionStatus(
    sessionId: string,
    newStatus: "Approved" | "Declined",
    comment?: string
  ): Promise<SessionResponse> {
    if (!sessionId) {
      throw new Error("sessionId is required");
    }

    return this.makeAuthenticatedRequest({
      url: `${this.baseUrl}/v1/session/${sessionId}/update-status/`,
      method: "PATCH",
      data: {
        new_status: newStatus,
        comment,
      },
      context: "status update",
    });
  }

  /**
   * Retrieves details of an existing session
   * @param sessionId - The ID of the session to retrieve
   * @returns Promise resolving to the session data
   * @throws Error if session retrieval fails
   */
  public async getSession(sessionId: string): Promise<SessionDecision> {
    if (!sessionId) {
      throw new Error("sessionId is required");
    }

    return this.makeAuthenticatedRequest({
      url: `${this.baseUrl}/v1/session/${sessionId}/decision/`,
      method: "GET",
      context: "session retrieval",
    });
  }

  /**
   * Verifies the signature of a webhook payload
   * @param headers - The headers from the webhook request
   * @param rawBody - The raw body of the webhook request
   * @returns The parsed webhook event data
   * @throws Error if signature verification fails
   */
  public verifyWebhookSignature(
    headers: WebhookHeaders,
    rawBody: string
  ): WebhookEvent {
    if (!this.webhookSecret) {
      throw new Error(
        "DIDIT_WEBHOOK_SECRET is required for webhook verification"
      );
    }

    const signature = headers["x-signature"];
    const timestamp = headers["x-timestamp"];

    // Ensure all required data is present
    if (!signature || !timestamp || !rawBody) {
      throw new Error("Missing required webhook verification data");
    }

    // Validate the timestamp to ensure the request is fresh (within 5 minutes)
    const currentTime = Math.floor(Date.now() / 1000);
    const incomingTime = parseInt(timestamp, 10);
    if (Math.abs(currentTime - incomingTime) > 300) {
      throw new Error("Request timestamp is stale");
    }

    // Generate an HMAC from the raw body using the shared secret
    const hmac = crypto.createHmac("sha256", this.webhookSecret);
    const expectedSignature = hmac.update(rawBody).digest("hex");

    // Compare using timingSafeEqual for security
    const expectedSignatureBuffer = Buffer.from(expectedSignature, "utf8");
    const providedSignatureBuffer = Buffer.from(signature, "utf8");

    if (
      expectedSignatureBuffer.length !== providedSignatureBuffer.length ||
      !crypto.timingSafeEqual(expectedSignatureBuffer, providedSignatureBuffer)
    ) {
      throw new Error("Invalid webhook signature");
    }

    // Signature is valid, parse and return the payload
    return JSON.parse(rawBody);
  }

  /**
   * Processes a webhook request by verifying its signature and parsing the payload
   * @param req - The request object containing headers and raw body
   * @returns The parsed and verified webhook event data
   * @throws Error if webhook processing fails
   */
  public processWebhook(req: {
    headers: WebhookHeaders;
    rawBody: string;
  }): WebhookEvent {
    if (!req.rawBody) {
      throw new Error(
        "Request raw body is required for webhook processing. Make sure to use the raw body parser middleware."
      );
    }

    const payload = this.verifyWebhookSignature(req.headers, req.rawBody);
    this.log("Webhook verified and processed", payload);
    return payload;
  }
}

/**
 * Creates and returns a middleware function for express that captures
 * the raw request body for webhook signature verification
 * @returns {Function} Express middleware
 */
function createRawBodyMiddleware(): (
  req: {
    on: (event: string, callback: (chunk: any) => void) => void;
    rawBody?: string;
  },
  res: any,
  next: () => void
) => void {
  return (
    req: {
      on: (event: string, callback: (chunk: any) => void) => void;
      rawBody?: string;
    },
    res: any,
    next: () => void
  ) => {
    let data: string = "";

    req.on("data", (chunk: string | Buffer) => {
      data += chunk;
    });

    req.on("end", () => {
      req.rawBody = data;
      next();
    });
  };
}

export { DiDiTClient, createRawBodyMiddleware };
