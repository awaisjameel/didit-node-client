import { SessionsResource } from "../resources/sessions";
import { DiditInvalidRequestError } from "../errors";
import type { HttpClient } from "../internal/http-client";

function makeHttp() {
  const request = jest.fn();
  return { http: { request } as unknown as HttpClient, request };
}

describe("SessionsResource", () => {
  describe("create", () => {
    it("requires workflow_id", async () => {
      const { http } = makeHttp();
      const sessions = new SessionsResource(http);
      // @ts-expect-error intentionally omitting the required field
      await expect(sessions.create({})).rejects.toThrow(DiditInvalidRequestError);
    });

    it("POSTs to /v3/session/ with the given payload", async () => {
      const { http, request } = makeHttp();
      request.mockResolvedValue({ data: { session_id: "s_1" }, status: 201, headers: {} });
      const sessions = new SessionsResource(http);

      await sessions.create({
        workflow_id: "wf_1",
        vendor_data: "user-123",
        callback: "https://cb",
      });

      expect(request).toHaveBeenCalledWith(
        expect.objectContaining({
          method: "POST",
          path: "/v3/session/",
          body: expect.objectContaining({
            workflow_id: "wf_1",
            vendor_data: "user-123",
            callback: "https://cb",
          }),
        }),
      );
    });

    it("base64-encodes a Buffer portrait_image automatically", async () => {
      const { http, request } = makeHttp();
      request.mockResolvedValue({ data: {}, status: 201, headers: {} });
      const sessions = new SessionsResource(http);
      const buffer = Buffer.from("fake-image-bytes");

      await sessions.create({ workflow_id: "wf_1", portrait_image: buffer });

      const sentBody = request.mock.calls[0][0].body;
      expect(sentBody.portrait_image).toBe(buffer.toString("base64"));
    });

    it("rejects a portrait_image Buffer larger than 2MB", async () => {
      const { http } = makeHttp();
      const sessions = new SessionsResource(http);
      const oversized = Buffer.alloc(2 * 1024 * 1024 + 1);

      await expect(
        sessions.create({ workflow_id: "wf_1", portrait_image: oversized }),
      ).rejects.toThrow(DiditInvalidRequestError);
    });

    it("returns the created session", async () => {
      const { http, request } = makeHttp();
      const session = { session_id: "s_1", status: "Not Started" };
      request.mockResolvedValue({ data: session, status: 201, headers: {} });
      const sessions = new SessionsResource(http);

      await expect(sessions.create({ workflow_id: "wf_1" })).resolves.toEqual(session);
    });
  });

  describe("retrieve", () => {
    it("requires a sessionId", async () => {
      const { http } = makeHttp();
      const sessions = new SessionsResource(http);
      await expect(sessions.retrieve("")).rejects.toThrow(DiditInvalidRequestError);
    });

    it("GETs the decision endpoint with the session id URL-encoded", async () => {
      const { http, request } = makeHttp();
      request.mockResolvedValue({ data: { session_id: "s 1" }, status: 200, headers: {} });
      const sessions = new SessionsResource(http);

      await sessions.retrieve("s 1");

      expect(request).toHaveBeenCalledWith(
        expect.objectContaining({ method: "GET", path: "/v3/session/s%201/decision/" }),
      );
    });
  });

  describe("list / listAll", () => {
    it("joins array filters into comma-separated query params", async () => {
      const { http, request } = makeHttp();
      request.mockResolvedValue({
        data: { count: 0, next: null, previous: null, results: [] },
        status: 200,
        headers: {},
      });
      const sessions = new SessionsResource(http);

      await sessions.list({ status: ["Approved", "In Review"], country: ["ESP", "USA"] });

      expect(request).toHaveBeenCalledWith(
        expect.objectContaining({
          method: "GET",
          path: "/v3/sessions/",
          query: expect.objectContaining({ status: "Approved,In Review", country: "ESP,USA" }),
        }),
      );
    });

    it("drops undefined/null filters from the query", async () => {
      const { http, request } = makeHttp();
      request.mockResolvedValue({
        data: { count: 0, next: null, previous: null, results: [] },
        status: 200,
        headers: {},
      });
      const sessions = new SessionsResource(http);

      await sessions.list({ vendor_data: undefined, search: "jane" });

      const query = request.mock.calls[0][0].query;
      expect(query).not.toHaveProperty("vendor_data");
      expect(query.search).toBe("jane");
    });

    it("listAll transparently follows pagination", async () => {
      const { http, request } = makeHttp();
      request
        .mockResolvedValueOnce({
          data: {
            count: 3,
            next: "https://.../v3/sessions/?offset=2",
            previous: null,
            results: [{ session_id: "1" }, { session_id: "2" }],
          },
          status: 200,
          headers: {},
        })
        .mockResolvedValueOnce({
          data: { count: 3, next: null, previous: null, results: [{ session_id: "3" }] },
          status: 200,
          headers: {},
        });
      const sessions = new SessionsResource(http);

      const ids: string[] = [];
      for await (const item of sessions.listAll({ limit: 2 })) {
        ids.push(item.session_id);
      }

      expect(ids).toEqual(["1", "2", "3"]);
      expect(request).toHaveBeenCalledTimes(2);
      expect(request.mock.calls[1][0].query).toEqual(
        expect.objectContaining({ limit: 2, offset: 2 }),
      );
    });

    it("listAll stops on an empty page even if `next` is truthy (defensive)", async () => {
      const { http, request } = makeHttp();
      request.mockResolvedValueOnce({
        data: { count: 0, next: "https://.../ignored", previous: null, results: [] },
        status: 200,
        headers: {},
      });
      const sessions = new SessionsResource(http);

      const items = [];
      for await (const item of sessions.listAll()) items.push(item);

      expect(items).toEqual([]);
      expect(request).toHaveBeenCalledTimes(1);
    });
  });

  describe("updateStatus", () => {
    it("requires email_address when send_email is true", async () => {
      const { http } = makeHttp();
      const sessions = new SessionsResource(http);

      await expect(
        sessions.updateStatus("s_1", { new_status: "Approved", send_email: true }),
      ).rejects.toThrow(DiditInvalidRequestError);
    });

    it("PATCHes update-status with the payload", async () => {
      const { http, request } = makeHttp();
      request.mockResolvedValue({ data: { session_id: "s_1" }, status: 200, headers: {} });
      const sessions = new SessionsResource(http);

      await sessions.updateStatus("s_1", { new_status: "Declined", comment: "Duplicate" });

      expect(request).toHaveBeenCalledWith(
        expect.objectContaining({
          method: "PATCH",
          path: "/v3/session/s_1/update-status/",
          body: { new_status: "Declined", comment: "Duplicate" },
        }),
      );
    });
  });

  describe("updateData / updatePoaData / updateKybCompanyData", () => {
    it("PATCHes update-data", async () => {
      const { http, request } = makeHttp();
      request.mockResolvedValue({ data: {}, status: 200, headers: {} });
      const sessions = new SessionsResource(http);

      await sessions.updateData("s_1", { first_name: "John" });

      expect(request).toHaveBeenCalledWith(
        expect.objectContaining({ method: "PATCH", path: "/v3/session/s_1/update-data/" }),
      );
    });

    it("PATCHes update-poa-data", async () => {
      const { http, request } = makeHttp();
      request.mockResolvedValue({ data: {}, status: 200, headers: {} });
      const sessions = new SessionsResource(http);

      await sessions.updatePoaData("s_1", { issuer: "Iberdrola" });

      expect(request).toHaveBeenCalledWith(
        expect.objectContaining({ method: "PATCH", path: "/v3/session/s_1/update-poa-data/" }),
      );
    });

    it("PATCHes kyb/{companyUuid}/update-data and requires both ids", async () => {
      const { http, request } = makeHttp();
      request.mockResolvedValue({ data: {}, status: 200, headers: {} });
      const sessions = new SessionsResource(http);

      await sessions.updateKybCompanyData("s_1", "co_1", { company_name: "Acme" });

      expect(request).toHaveBeenCalledWith(
        expect.objectContaining({ method: "PATCH", path: "/v3/session/s_1/kyb/co_1/update-data/" }),
      );
      await expect(sessions.updateKybCompanyData("s_1", "", {})).rejects.toThrow(
        DiditInvalidRequestError,
      );
    });
  });

  describe("generatePdf", () => {
    it("requests the generate-pdf endpoint as arraybuffer and returns a Buffer", async () => {
      const { http, request } = makeHttp();
      const bytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]); // %PDF
      request.mockResolvedValue({ data: bytes.buffer, status: 200, headers: {} });
      const sessions = new SessionsResource(http);

      const pdf = await sessions.generatePdf("s_1");

      expect(request).toHaveBeenCalledWith(
        expect.objectContaining({
          method: "GET",
          path: "/v3/session/s_1/generate-pdf/",
          responseType: "arraybuffer",
        }),
      );
      expect(pdf).toBeInstanceOf(Buffer);
      expect(pdf.subarray(0, 4)).toEqual(Buffer.from("%PDF"));
    });
  });
});
