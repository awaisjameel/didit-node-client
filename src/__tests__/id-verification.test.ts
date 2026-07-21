import { IdVerificationResource } from "../resources/id-verification";
import { DiditInvalidRequestError } from "../errors";
import type { HttpClient } from "../internal/http-client";

function makeHttp() {
  const request = jest.fn();
  return { http: { request } as unknown as HttpClient, request };
}

describe("IdVerificationResource", () => {
  it("requires front_image", async () => {
    const { http } = makeHttp();
    const resource = new IdVerificationResource(http);

    // @ts-expect-error intentionally omitting the required field
    await expect(resource.verify({})).rejects.toThrow(DiditInvalidRequestError);
  });

  it("POSTs multipart form-data to /v3/id-verification/", async () => {
    const { http, request } = makeHttp();
    request.mockResolvedValue({
      data: {
        request_id: "req_1",
        id_verification: { status: "Approved", warnings: [] },
        created_at: "now",
      },
      status: 200,
      headers: {},
    });
    const resource = new IdVerificationResource(http);

    const result = await resource.verify({
      front_image: Buffer.from("front-bytes"),
      back_image: Buffer.from("back-bytes"),
      perform_document_liveness: true,
      vendor_data: "user-123",
      metadata: { source: "mobile" },
    });

    expect(request).toHaveBeenCalledWith(
      expect.objectContaining({ method: "POST", path: "/v3/id-verification/" }),
    );
    const call = request.mock.calls[0][0];
    expect(call.formData).toBeDefined();
    expect(typeof call.formData.getHeaders).toBe("function");
    expect(result.id_verification.status).toBe("Approved");
  });

  it("accepts { data, filename, contentType } image descriptors", async () => {
    const { http, request } = makeHttp();
    request.mockResolvedValue({
      data: {
        request_id: "req_1",
        id_verification: { status: "Approved", warnings: [] },
        created_at: "now",
      },
      status: 200,
      headers: {},
    });
    const resource = new IdVerificationResource(http);

    await resource.verify({
      front_image: {
        data: Buffer.from("bytes"),
        filename: "passport.png",
        contentType: "image/png",
      },
    });

    expect(request).toHaveBeenCalled();
  });
});
