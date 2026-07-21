/**
 * Business verification (KYB): create a session against a KYB workflow, then correct a
 * registry-extracted company field after the fact.
 *
 * Usage: DIDIT_KYB_WORKFLOW_ID=... node examples/kyb-verification.js
 */
require("dotenv").config();
const { DiditClient } = require("didit-node-client");

async function main() {
  const didit = new DiditClient({ apiKey: process.env.DIDIT_API_KEY });

  const session = await didit.sessions.create({
    workflow_id: process.env.DIDIT_KYB_WORKFLOW_ID,
    vendor_data: "company-456",
    callback: "https://your-app.com/verification/callback",
    expected_details: {
      company_name: "Acme Holdings S.L.",
      registry_country: "ES",
      registration_number: "B12345678",
    },
  });

  console.log(`Created ${session.session_kind} session:`, session.url);

  const decision = await didit.sessions.retrieve(session.session_id);
  const company = decision.registry_checks?.[0];
  if (company?.company_uuid) {
    // Correct a field the registry lookup got wrong, e.g. after manual review.
    await didit.sessions.updateKybCompanyData(session.session_id, company.company_uuid, {
      alternative_names: "Acme Ltd, Acme Group",
    });
    console.log("Updated company record", company.company_uuid);
  }
}

main().catch((error) => {
  console.error("KYB verification error:", error.message);
  process.exitCode = 1;
});
