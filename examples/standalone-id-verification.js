/**
 * Verifies a single document image synchronously via the standalone ID Verification API —
 * no hosted session required. Useful when you already collect the document yourself (e.g.
 * your own upload UI) and just need Didit to check and extract it.
 *
 * Usage: node examples/standalone-id-verification.js <path-to-front-image> [path-to-back-image]
 */
const fs = require("fs");
const { DiditClient } = require("didit-node-client");

async function main() {
  const [frontPath, backPath] = process.argv.slice(2);
  if (!frontPath) {
    console.error("Usage: node examples/standalone-id-verification.js <front-image> [back-image]");
    process.exit(1);
  }

  const didit = new DiditClient({ apiKey: process.env.DIDIT_API_KEY });

  const result = await didit.idVerification.verify({
    front_image: fs.readFileSync(frontPath),
    back_image: backPath ? fs.readFileSync(backPath) : undefined,
    perform_document_liveness: true,
    vendor_data: "user-123",
  });

  const { id_verification: doc } = result;
  console.log(`Status: ${doc.status}`);
  console.log(`Document: ${doc.document_type} #${doc.document_number}`);
  console.log(`Name: ${doc.full_name}, DOB: ${doc.date_of_birth}`);

  if (doc.warnings.length > 0) {
    console.log(
      "Warnings:",
      doc.warnings.map((w) => `${w.risk} (${w.log_type})`),
    );
  }
}

main().catch((error) => {
  console.error("Verification error:", error.message);
  process.exitCode = 1;
});
