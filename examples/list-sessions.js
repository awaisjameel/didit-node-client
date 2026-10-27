/**
 * Lists sessions with filters, and shows the auto-paginating async iterator so you never
 * have to juggle `offset`/`next` yourself.
 *
 * Usage: node examples/list-sessions.js
 */
const { DiditClient } = require("didit-node-client");

async function main() {
  const didit = new DiditClient({ apiKey: process.env.DIDIT_API_KEY });

  // One page:
  const page = await didit.sessions.list({ status: ["Approved", "In Review"], limit: 20 });
  console.log(`First page: ${page.results.length} of ${page.count} total sessions`);

  // Every matching session, across all pages:
  let count = 0;
  for await (const session of didit.sessions.listAll({ status: "In Review" })) {
    count += 1;
    console.log(session.session_id, session.status, session.full_name ?? session.company_name);
  }
  console.log(`Reviewed ${count} sessions currently In Review.`);
}

main().catch((error) => {
  console.error("Error listing sessions:", error.message);
  process.exitCode = 1;
});
