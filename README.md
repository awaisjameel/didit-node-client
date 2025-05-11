# DiDiT Node.js Client

A Node.js client library for integrating with the DiDiT verification API. This client handles authentication, session management, PDF report generation, and webhook processing.

## Installation

```bash
npm install didit-node-client
```

## Configuration

```typescript
import { DiDiTClient } from "didit-node-client";

const client = new DiDiTClient({
  clientId: "your_client_id",
  clientSecret: "your_client_secret",
  webhookSecret: "your_webhook_secret", // Required for webhook verification
  baseUrl: "https://verification.didit.me", // Optional
  authUrl: "https://apx.didit.me", // Optional
  tokenExpiryBuffer: 300, // Optional: Buffer time in seconds before token expiry
  timeout: 10000, // Optional: Request timeout in milliseconds
  debug: false, // Optional: Enable debug logging
});
```

Environment variables:

- `DIDIT_CLIENT_ID`
- `DIDIT_CLIENT_SECRET`
- `DIDIT_WEBHOOK_SECRET`
- `DIDIT_BASE_URL`
- `DIDIT_AUTH_URL`

## Features

### Session Management

```typescript
// Create a new verification session
const session = await client.createSession(
  "https://your-callback-url.com",
  "123", // optional Unique identifier or data for the vendor, typically the identifier of the user trying to verify.
  {
    features: "OCR + NFC + FACE", // Optional features configuration
  }
);

// Get session details and verification decision
const sessionDecision = await client.getSession("session_id");

// Update session status (Approve/Decline)
const updatedSession = await client.updateSessionStatus(
  "session_id",
  "Approved",
  "Verification completed successfully" // Optional comment
);

// Generate PDF report
const pdfBuffer = await client.generateSessionPDF("session_id");
```

### Webhook Processing

```typescript
import express from "express";
import { createRawBodyMiddleware, DiDiTClient } from "didit-node-client";

const app = express();
const client = new DiDiTClient({
  webhookSecret: "your_webhook_secret",
});

// Add raw body middleware for webhook signature verification
app.use("/webhook", createRawBodyMiddleware());

app.post("/webhook", (req, res) => {
  try {
    const payload = client.processWebhook(req);
    console.log("Webhook received:", payload);

    // Handle different webhook events
    switch (payload.event_type) {
      case "session.completed":
        // Handle completed session
        break;
      case "session.declined":
        // Handle declined session
        break;
      // ... handle other events
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Webhook error:", error);
    res.status(400).json({ error: error.message });
  }
});
```

## Error Handling

The client includes comprehensive error handling with context:

```typescript
try {
  const session = await client.createSession("https://callback-url.com");
} catch (error) {
  console.error("Error:", error.message);
  console.error("Context:", error.context);
  console.error("Original Error:", error.originalError);
  console.error("API Response:", error.response?.data);
}
```

## Authentication

The client automatically handles:

- Token acquisition and caching
- Token refresh before expiry
- Token rotation
- Request authentication

## TypeScript Support

Import types for better type safety:

```typescript
import {
  DiDiTClient,
  SessionOptions,
  WebhookEvent,
  SessionDecision,
} from "didit-node-client";
```

## Security Best Practices

1. Store credentials securely:

   - Use environment variables
   - Never commit secrets to source control
   - Use secure secret management in production

2. Webhook security:

   - Always verify webhook signatures
   - Validate webhook timestamp freshness
   - Use HTTPS endpoints

3. General security:
   - Use HTTPS for callback URLs
   - Keep dependencies updated
   - Implement proper error handling

## Documentation

For detailed API documentation, visit:

- [DiDiT API Documentation](https://docs.didit.me)
- [API Reference](https://api.didit.me/docs)

## License

MIT

## Support

For issues and feature requests, please visit our [GitHub repository](https://github.com/awaisjameel/didit-node-client/issues).
