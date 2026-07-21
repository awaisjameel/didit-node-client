import {
  createAPIError,
  DiditAPIError,
  DiditAuthenticationError,
  DiditError,
  DiditNotFoundError,
  DiditRateLimitError,
  DiditServerError,
  DiditValidationError,
} from "../errors";

function details(status: number) {
  return { status, request: "GET /v3/session/x/decision/", body: { message: "boom" }, headers: {} };
}

describe("createAPIError", () => {
  it("maps 400 to DiditValidationError", () => {
    expect(createAPIError(400, "msg", details(400))).toBeInstanceOf(DiditValidationError);
  });

  it("maps 401 and 403 to DiditAuthenticationError", () => {
    expect(createAPIError(401, "msg", details(401))).toBeInstanceOf(DiditAuthenticationError);
    expect(createAPIError(403, "msg", details(403))).toBeInstanceOf(DiditAuthenticationError);
  });

  it("maps 404 to DiditNotFoundError", () => {
    expect(createAPIError(404, "msg", details(404))).toBeInstanceOf(DiditNotFoundError);
  });

  it("maps 429 to DiditRateLimitError and carries rate-limit fields", () => {
    const error = createAPIError(429, "msg", {
      ...details(429),
      retryAfter: 12,
      limit: 600,
      remaining: 0,
      reset: 60,
    });
    expect(error).toBeInstanceOf(DiditRateLimitError);
    expect((error as DiditRateLimitError).retryAfter).toBe(12);
    expect((error as DiditRateLimitError).limit).toBe(600);
  });

  it("maps 5xx to DiditServerError", () => {
    expect(createAPIError(500, "msg", details(500))).toBeInstanceOf(DiditServerError);
    expect(createAPIError(503, "msg", details(503))).toBeInstanceOf(DiditServerError);
  });

  it("falls back to plain DiditAPIError for unmapped statuses", () => {
    const error = createAPIError(418, "msg", details(418));
    expect(error).toBeInstanceOf(DiditAPIError);
    expect(error).not.toBeInstanceOf(DiditValidationError);
  });

  it("every API error is also a DiditError", () => {
    expect(createAPIError(500, "msg", details(500))).toBeInstanceOf(DiditError);
  });

  it("preserves status, body, headers, and request on the error instance", () => {
    const error = createAPIError(404, "Session not found", details(404)) as DiditNotFoundError;
    expect(error.status).toBe(404);
    expect(error.body).toEqual({ message: "boom" });
    expect(error.request).toBe("GET /v3/session/x/decision/");
    expect(error.message).toBe("Session not found");
  });
});
