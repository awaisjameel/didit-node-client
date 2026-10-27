/**
 * Creates a hosted verification session and shows two ways to learn the outcome:
 * polling `sessions.retrieve()`, and (recommended in production) a webhook — see
 * webhook-server.js for that flow.
 *
 * Usage: DIDIT_API_KEY=... DIDIT_WORKFLOW_ID=... node examples/basic-verification.js
 */
const { DiditClient } = require("didit-node-client");

async function main() {
  const didit = new DiditClient({
    apiKey: process.env.DIDIT_API_KEY,
    debug: true,
  });

  const session = await didit.sessions.create({
    workflow_id: process.env.DIDIT_WORKFLOW_ID,
    vendor_data: "user-123", // your own user id — enables session reuse + easy correlation
    callback: "https://your-app.com/verification/callback",
  });

  console.log("Session created. Send the user here to verify:");
  console.log(session.url);

  // In a real app you would NOT poll immediately after creating a session — the user
  // hasn't verified yet. This just demonstrates retrieving a decision once one exists,
  // e.g. from a background job, an admin dashboard, or after a webhook tells you it's ready.
  const decision = await didit.sessions.retrieve(session.session_id);
  console.log(`Session ${decision.session_id} status: ${decision.status}`);

  if (decision.status === "Approved") {
    const identity = decision.id_verifications?.[0];
    const face = decision.face_matches?.[0];
    console.log("Verified user:", {
      name: identity?.full_name,
      document: identity?.document_type,
      faceMatchScore: face?.score,
    });
  }
}

main().catch((error) => {
  console.error("Verification error:", error.message);
  if (error.status) console.error("HTTP status:", error.status, error.body);
  process.exitCode = 1;
});
