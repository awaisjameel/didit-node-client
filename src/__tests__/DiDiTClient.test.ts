import { DiDiTClient } from "../index";
import axios from "axios";
import crypto from "crypto";

// Mock axios
jest.mock("axios");
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock crypto
jest.mock("crypto", () => ({
  createHmac: jest.fn().mockReturnValue({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn().mockReturnValue("mock-signature"),
  }),
  timingSafeEqual: jest.fn(),
}));

describe("DiDiTClient", () => {
  let client: DiDiTClient;
  const mockConfig = {
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    webhookSecret: "test-webhook-secret",
  };

  beforeEach(() => {
    client = new DiDiTClient(mockConfig);
    jest.clearAllMocks();
  });

  describe("Authentication", () => {
    it("should get access token successfully", async () => {
      const mockToken = "mock-access-token";
      mockedAxios.create.mockReturnValue({
        post: jest.fn().mockResolvedValue({
          data: { access_token: mockToken, expires_in: 3600 },
        }),
        request: jest.fn(),
      } as any);

      const token = await client.getAccessToken();
      expect(token).toBe(mockToken);
    });

    it("should use cached token if not expired", async () => {
      // First call to set the cache
      mockedAxios.create.mockReturnValue({
        post: jest.fn().mockResolvedValue({
          data: { access_token: "cached-token", expires_in: 3600 },
        }),
        request: jest.fn(),
      } as any);

      await client.getAccessToken();
      const secondToken = await client.getAccessToken();

      expect(secondToken).toBe("cached-token");
      expect(mockedAxios.create).toHaveBeenCalledTimes(1);
    });
  });

  describe("Session Management", () => {
    beforeEach(() => {
      mockedAxios.create.mockReturnValue({
        post: jest.fn().mockResolvedValue({
          data: { access_token: "test-token", expires_in: 3600 },
        }),
        request: jest.fn().mockResolvedValue({
          data: { session_id: "test-session" },
        }),
      } as any);
    });

    it("should create a session", async () => {
      const session = await client.createSession("https://callback.url", {
        test: "data",
      });
      expect(session).toEqual({ session_id: "test-session" });
    });

    it("should get session details", async () => {
      const session = await client.getSession("test-session-id");
      expect(session).toEqual({ session_id: "test-session" });
    });

    it("should update session status", async () => {
      const updated = await client.updateSessionStatus(
        "test-session-id",
        "Approved",
        "Test comment"
      );
      expect(updated).toEqual({ session_id: "test-session" });
    });

    it("should generate session PDF", async () => {
      const mockPdfData = new Uint8Array([80, 68, 70]); // PDF magic numbers
      mockedAxios.create.mockReturnValue({
        post: jest.fn().mockResolvedValue({
          data: { access_token: "test-token", expires_in: 3600 },
        }),
        request: jest.fn().mockResolvedValue({
          data: mockPdfData,
        }),
      } as any);

      const pdf = await client.generateSessionPDF("test-session-id");
      expect(pdf).toBeInstanceOf(Buffer);
      // Just verify it contains PDF magic numbers at the start
      expect(pdf.slice(0, 3)).toEqual(Buffer.from([80, 68, 70])); // "PDF"
    });
  });

  describe("Webhook Handling", () => {
    it("should verify webhook signature", () => {
      const mockHeaders = {
        "x-signature": "mock-signature",
        "x-timestamp": Math.floor(Date.now() / 1000).toString(),
      };
      const mockBody = JSON.stringify({ event: "test" });

      (crypto.timingSafeEqual as jest.Mock).mockReturnValue(true);

      const result = client.verifyWebhookSignature(mockHeaders, mockBody);
      expect(result).toEqual({ event: "test" });
    });

    it("should process webhook request", () => {
      const mockReq = {
        headers: {
          "x-signature": "mock-signature",
          "x-timestamp": Math.floor(Date.now() / 1000).toString(),
        },
        rawBody: JSON.stringify({ event: "test" }),
      };

      (crypto.timingSafeEqual as jest.Mock).mockReturnValue(true);

      const result = client.processWebhook(mockReq);
      expect(result).toEqual({ event: "test" });
    });

    it("should reject invalid webhook signatures", () => {
      const mockHeaders = {
        "x-signature": "invalid-signature",
        "x-timestamp": Math.floor(Date.now() / 1000).toString(),
      };
      const mockBody = JSON.stringify({ event: "test" });

      (crypto.timingSafeEqual as jest.Mock).mockReturnValue(false);

      expect(() => {
        client.verifyWebhookSignature(mockHeaders, mockBody);
      }).toThrow("Invalid webhook signature");
    });
  });

  describe("Error Handling", () => {
    it("should handle API errors properly", async () => {
      mockedAxios.create.mockReturnValue({
        request: jest.fn().mockRejectedValue({
          response: {
            data: { error: "API Error" },
          },
          message: "Request failed",
        }),
      } as any);

      await expect(client.getSession("test-id")).rejects.toThrow(
        "DiDiT session retrieval error"
      );
    });
  });
});
