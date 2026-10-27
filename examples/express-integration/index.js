/**
 * A slightly fuller Express app: start a session, poll its status, receive webhooks, and
 * download the PDF report — the four calls most integrations need.
 *
 * Usage: DIDIT_API_KEY=... DIDIT_WEBHOOK_SECRET=... node examples/express-integration/index.js
 */
const express = require("express");
const { DiditClient, createRawBodyMiddleware } = require("didit-node-client");

const app = express();
const port = process.env.PORT || 3000;

const didit = new DiditClient({
  apiKey: process.env.DIDIT_API_KEY,
  webhookSecret: process.env.DIDIT_WEBHOOK_SECRET,
  debug: true,
});

// Webhook route: mount the raw-body middleware BEFORE express.json() touches this path.
app.post("/webhooks/didit", createRawBodyMiddleware(), (req, res) => {
  try {
    const { event } = didit.webhooks.constructEvent(req.rawBody, req.headers);
    if (event.webhook_type === "status.updated") {
      console.log(`Session ${event.session_id} -> ${event.status}`);
    }
    res.status(200).json({ received: true });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.use(express.json());

// Start a verification session for the authenticated user.
app.post("/verify", async (req, res) => {
  try {
    const { userId, redirectUrl } = req.body;
    if (!userId || !redirectUrl) {
      return res.status(400).json({ error: "userId and redirectUrl are required" });
    }

    const session = await didit.sessions.create({
      workflow_id: process.env.DIDIT_WORKFLOW_ID,
      vendor_data: userId,
      callback: redirectUrl,
    });

    res.json({ verificationUrl: session.url, sessionId: session.session_id });
  } catch (error) {
    res.status(error.status ?? 500).json({ error: error.message });
  }
});

// Check a session's current status/decision.
app.get("/verify/:sessionId", async (req, res) => {
  try {
    const decision = await didit.sessions.retrieve(req.params.sessionId);
    res.json(decision);
  } catch (error) {
    res.status(error.status ?? 500).json({ error: error.message });
  }
});

// Download the compliance PDF report for a finished session.
app.get("/verify/:sessionId/report", async (req, res) => {
  try {
    const pdfBuffer = await didit.sessions.generatePdf(req.params.sessionId);
    res.type("application/pdf").send(pdfBuffer);
  } catch (error) {
    res.status(error.status ?? 500).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
