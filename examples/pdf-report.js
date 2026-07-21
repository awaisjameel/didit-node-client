/**
 * Generates and saves a compliance-ready PDF report for a completed session.
 * Only eligible for sessions in an eligible status (KYC: Approved, Declined, In Review,
 * Kyc Expired; KYB: Approved, Declined, In Review) — other statuses return a 403.
 *
 * Usage: node examples/pdf-report.js <sessionId>
 */
require("dotenv").config();
const fs = require("fs/promises");
const path = require("path");
const { DiditClient } = require("didit-node-client");

async function generateAndSaveReport(sessionId) {
  const didit = new DiditClient({ apiKey: process.env.DIDIT_API_KEY, debug: true });

  const decision = await didit.sessions.retrieve(sessionId);
  console.log(`Generating report for session ${decision.session_id} (status: ${decision.status})`);

  const pdfBuffer = await didit.sessions.generatePdf(sessionId);

  const reportsDir = path.join(__dirname, "reports");
  await fs.mkdir(reportsDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filePath = path.join(reportsDir, `verification-${sessionId}-${timestamp}.pdf`);
  await fs.writeFile(filePath, pdfBuffer);

  console.log("PDF report saved:", filePath);
  return filePath;
}

const sessionId = process.argv[2];
if (!sessionId) {
  console.error("Usage: node examples/pdf-report.js <sessionId>");
  process.exit(1);
}

generateAndSaveReport(sessionId).catch((error) => {
  console.error("Failed to generate report:", error.message);
  process.exitCode = 1;
});
