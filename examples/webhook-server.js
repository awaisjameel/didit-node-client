/**
 * Minimal Express webhook receiver. Verifies the signature, then branches on webhook_type
 * and session status. Mount createRawBodyMiddleware() ONLY on the webhook route, before any
 * body parser that would otherwise consume the request stream.
 *
 * Usage: DIDIT_WEBHOOK_SECRET=... node examples/webhook-server.js
 */
require("dotenv").config();
const express = require("express");
const { DiditClient, createRawBodyMiddleware } = require("didit-node-client");

const app = express();
const port = process.env.PORT || 3000;

const didit = new DiditClient({
  apiKey: process.env.DIDIT_API_KEY,
  webhookSecret: process.env.DIDIT_WEBHOOK_SECRET,
  debug: true,
});

app.post("/webhooks/didit", createRawBodyMiddleware(), (req, res) => {
  let verification;
  try {
    verification = didit.webhooks.constructEvent(req.rawBody, req.headers);
  } catch (error) {
    // Wrong secret, tampered payload, stale timestamp, or malformed body.
    console.error("Webhook rejected:", error.message);
    return res.status(400).json({ error: error.message });
  }

  const { event, verifiedWith, isTest } = verification;
  console.log(`Verified webhook via ${verifiedWith} scheme${isTest ? " (test delivery)" : ""}`);

  switch (event.webhook_type) {
    case "status.updated":
      handleStatusUpdate(event);
      break;
    case "data.updated":
      console.log(`Session ${event.session_id} data corrected post-verification.`);
      break;
    case "user.status.updated":
      console.log(
        `User ${event.vendor_user_id} status: ${event.previous_status} -> ${event.status}`,
      );
      break;
    case "transaction.created":
    case "transaction.status.updated":
      console.log(`Transaction ${event.transaction_id} status: ${event.status}`);
      break;
    default:
      console.log("Unhandled webhook type:", event.webhook_type);
  }

  // Respond fast (< 5s) and do heavier work asynchronously — Didit retries on non-2xx or timeout.
  res.status(200).json({ received: true });
});

function handleStatusUpdate(event) {
  switch (event.status) {
    case "Approved":
      console.log(`Session ${event.session_id} approved.`, {
        vendorData: event.vendor_data,
        fullName: event.decision?.id_verifications?.[0]?.full_name,
      });
      break;
    case "Declined":
      console.log(`Session ${event.session_id} declined — route to compliance review.`);
      break;
    case "In Review":
      console.log(`Session ${event.session_id} needs manual review.`);
      break;
    case "Resubmitted":
      console.log(`Session ${event.session_id} resubmission requested:`, event.resubmit_info);
      break;
    default:
      console.log(`Session ${event.session_id} status: ${event.status}`);
  }
}

app.listen(port, () => {
  console.log(`Webhook server listening at http://localhost:${port}/webhooks/didit`);
});
