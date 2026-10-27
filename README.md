# didit-node-client

[![npm version](https://img.shields.io/npm/v/didit-node-client.svg)](https://www.npmjs.com/package/didit-node-client)
[![npm downloads](https://img.shields.io/npm/dm/didit-node-client.svg)](https://www.npmjs.com/package/didit-node-client)
[![license](https://img.shields.io/npm/l/didit-node-client.svg)](./LICENSE)
[![types](https://img.shields.io/npm/types/didit-node-client.svg)](./dist/index.d.ts)

A modern, fully-typed Node.js client for the [Didit](https://didit.me) Identity Verification
API (**v3**) — hosted KYC/KYB sessions, standalone document verification, and secure webhook
handling, with sane defaults and no surprises.

```ts
import { DiditClient } from "didit-node-client";

const didit = new DiditClient({ apiKey: process.env.DIDIT_API_KEY });

const session = await didit.sessions.create({
  workflow_id: process.env.DIDIT_WORKFLOW_ID!,
  vendor_data: user.id,
  callback: "https://example.com/verification/callback",
});

// Redirect the user here to complete verification:
res.redirect(session.url);
```

> **Upgrading?** Version 3 requires maintained Node 22/24/26 and full-payload webhook signatures. See [MIGRATION.md](./MIGRATION.md) for the 2.x and 1.x migration paths.

---

## Table of contents

- [Features](#features)
- [Installation](#installation)
- [Getting your credentials](#getting-your-credentials)
- [Configuration](#configuration)
- [Sessions API](#sessions-api)
  - [Create a session](#create-a-session)
  - [Retrieve a decision](#retrieve-a-decision)
  - [List &amp; paginate sessions](#list--paginate-sessions)
  - [Update status (approve / decline / resubmit)](#update-status-approve--decline--resubmit)
  - [Correct extracted data](#correct-extracted-data)
  - [Generate a PDF report](#generate-a-pdf-report)
- [Standalone ID Verification](#standalone-id-verification)
- [Webhooks](#webhooks)
  - [Express](#express)
  - [Any other framework](#any-other-framework)
  - [Event types](#event-types)
- [Error handling](#error-handling)
- [Retries, timeouts &amp; rate limits](#retries-timeouts--rate-limits)
- [TypeScript](#typescript)
- [Security best practices](#security-best-practices)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Features

- 🔑 **v3-native** — built against Didit's current `x-api-key` + `workflow_id` API, KYC and KYB alike.
- 🧩 **Full session lifecycle** — create, retrieve, list (with auto-pagination), approve/decline/resubmit, correct OCR/registry data, and render PDF reports.
- 🪪 **Standalone ID verification** — one-shot document checks without spinning up a hosted session.
- 🔐 **Robust webhooks** — authenticates the complete payload using canonical V2 or raw-body signatures, including signing-secret rotation, with freshness bound to signed timestamps.
- 🔁 **Automatic retries** — exponential backoff with jitter on network errors, `429`, and `5xx`, honoring `Retry-After`. Safe by default (only idempotent `GET`s retry automatically).
- 🎯 **End-to-end TypeScript** — every request and response is fully typed, including the full decision schema (`id_verifications`, `aml_screenings`, `face_matches`, `liveness_checks`, KYB `registry_checks`, ...).
- 📦 **Dual CJS/ESM** — works with `require()` and `import` out of the box, tree-shakeable.
- 🪶 **Small dependency footprint** — just `axios` and `form-data`.
- 🧵 **Cancellable** — every call accepts an `AbortSignal`.
- 🧪 **Well tested** — extensive unit tests covering HTTP retries, error mapping, and webhook signature verification (including tamper/replay rejection).

## Installation

```bash
npm install didit-node-client
```

Supports maintained Node.js **22, 24 and 26** (minimum 22.18.0 or 24.11.0 for those lines). `express` is an optional peer dependency, needed only if you use
[`createRawBodyMiddleware`](#express).

## Getting your credentials

1. Create an account in the [Didit Business Console](https://business.didit.me).
2. Build a verification workflow (KYC or KYB) and note its **Workflow ID**.
3. Generate an **API Key** under Settings → API Keys — this is a long-lived secret, backend-only.
4. (Optional, for webhooks) Configure a webhook destination and copy its **Webhook Secret**.

## Configuration

```ts
import { DiditClient } from "didit-node-client";

const didit = new DiditClient({
  apiKey: "your_api_key", // or set DIDIT_API_KEY
  webhookSecret: "your_webhook_secret", // or set DIDIT_WEBHOOK_SECRET — only needed for webhooks
  baseUrl: "https://verification.didit.me", // optional, for testing against a mock server
  timeout: 15_000, // optional, per-request timeout in ms (default 15000)
  maxRetries: 2, // optional, automatic retries for safe requests (default 2)
  debug: false, // optional, verbose logging with secrets redacted
});
```

`new DiditClient()` with no arguments works too, as long as the environment variables below are
set — handy for serverless/edge configs that inject env vars directly.

| Environment variable   | Maps to         | Required                     |
| ---------------------- | --------------- | ---------------------------- |
| `DIDIT_API_KEY`        | `apiKey`        | Yes (unless passed directly) |
| `DIDIT_WEBHOOK_SECRET` | `webhookSecret` | Only if using webhooks       |
| `DIDIT_BASE_URL`       | `baseUrl`       | No                           |

## Sessions API

The hosted flow: create a session, send your user to `session.url` to complete verification in
Didit's UI, then learn the result via [webhook](#webhooks) (recommended) or by retrieving the
decision directly.

### Create a session

```ts
const session = await didit.sessions.create({
  workflow_id: "wf_...", // required — selects KYC vs KYB and the verification steps
  vendor_data: user.id, // your own identifier; enables session reuse + easy correlation
  callback: "https://example.com/verification/callback",
  callback_method: "both", // "initiator" | "completer" | "both" — who gets redirected
  metadata: { plan: "pro" }, // arbitrary JSON, echoed back on the session and in webhooks
  language: "en",
  contact_details: { email: user.email, send_notification_emails: true },
  expected_details: { first_name: user.firstName, last_name: user.lastName },
});

session.url; // -> redirect or embed your user here
session.session_id; // -> store this alongside your user record
```

If `vendor_data` matches an unfinished session on the workflow's current published version,
Didit returns that session instead of creating a duplicate — safe to call more than once for
the same user.

`portrait_image` (for Face Match workflows) accepts a `Buffer` directly; the SDK base64-encodes
it for you:

```ts
await didit.sessions.create({
  workflow_id: "wf_...",
  portrait_image: fs.readFileSync("selfie.jpg"), // max 2MB
});
```

### Retrieve a decision

```ts
const decision = await didit.sessions.retrieve(session.session_id);

decision.status; // "Approved" | "Declined" | "In Review" | ...
decision.id_verifications?.[0]?.full_name;
decision.aml_screenings?.[0]?.hits;
decision.face_matches?.[0]?.score;
```

Feature results can be omitted or null until they run. Every feature result (`id_verifications`, `nfc_verifications`, `liveness_checks`,
`face_matches`, `aml_screenings`, `poa_verifications`, `phone_verifications`,
`email_verifications`, `ip_analyses`, `database_validations`, and the KYB-only
`registry_checks` / `document_verifications` / `key_people_checks`) is an array, `undefined`
or null until that feature runs. Media URLs (images/video) are **short-lived presigned links** — use
them promptly, or call `retrieve()` again for fresh ones.

### List & paginate sessions

```ts
// One page:
const page = await didit.sessions.list({ status: ["Approved", "In Review"], limit: 20 });

// Every matching session, transparently paginated:
for await (const session of didit.sessions.listAll({ workflow_id: "wf_..." })) {
  console.log(session.session_id, session.status);
}
```

Array filters (`status`, `workflow_id`, `country`, `document_type`) are automatically joined
into the comma-separated form the API expects. `listAll({ session_kind: "all" })` yields KYC sessions first, then KYB sessions, paginating each independently so capped KYB counts cannot truncate results.

### Update status (approve / decline / resubmit)

```ts
await didit.sessions.updateStatus(session.session_id, {
  new_status: "Approved",
  comment: "Manually cleared after review",
});

// Request resubmission of specific steps:
await didit.sessions.updateStatus(session.session_id, {
  new_status: "Resubmitted",
  nodes_to_resubmit: [{ node_id: "id_verification_1", feature: "ID_VERIFICATION" }],
  send_email: true,
  email_address: user.email,
});
```

This call is **not idempotent** — resending the same request returns a `400`. The session must
already be in a terminal-ish status (`Approved`, `Declined`, `In Review`, `Kyc Expired`,
`Abandoned`, or `Resubmitted`).

### Correct extracted data

Fix an OCR/registry field without re-running verification:

```ts
await didit.sessions.updateData(session.session_id, { first_name: "John", last_name: "Doe" });
await didit.sessions.updatePoaData(session.session_id, { issuer: "Iberdrola" });
await didit.sessions.updateKybCompanyData(session.session_id, companyUuid, {
  company_name: "Acme Corporation Limited",
});
```

Each of these fires a `data.updated` webhook.

### Generate a PDF report

```ts
const pdf = await didit.sessions.generatePdf(session.session_id); // Buffer
await fs.promises.writeFile(`session-${session.session_id}.pdf`, pdf);
```

Rate-limited to 50 requests/minute per API key; only available once a session reaches an
eligible status.

## Standalone ID Verification

Already collecting documents through your own UI and just need Didit to check one? Skip the
hosted session entirely:

```ts
const result = await didit.idVerification.verify({
  front_image: fs.readFileSync("front.jpg"), // Buffer, stream, or { data, filename, contentType }
  back_image: fs.readFileSync("back.jpg"),
  perform_document_liveness: true,
});

result.id_verification.status; // "Approved" | "Declined"
result.id_verification.full_name;
result.id_verification.warnings; // e.g. DOCUMENT_EXPIRED, MRZ_VALIDATION_FAILED
```

Rate-limited to 300 requests/minute per API key.

## Webhooks

`constructEvent` accepts full-payload `X-Signature-V2` and `X-Signature` signatures only, including their `-Previous` variants during secret rotation. Simple-only signatures are rejected. The signed body must contain a fresh `timestamp` (or a legacy signed `created_at`); an optional `X-Timestamp` must match it. Default clock tolerance is 300 seconds. `isTest` is an unsigned informational hint and must never bypass authorization.

```ts
const { event, verifiedWith, isTest } = didit.webhooks.constructEvent(rawBody, headers);
```

`rawBody` must be the **exact bytes** of the request body, before any JSON parsing —
re-stringifying a parsed body can break raw-body verification. Canonical V2 verification tolerates object key ordering and whitespace changes.

### Express

```ts
import express from "express";
import { DiditClient, createRawBodyMiddleware } from "didit-node-client";

const app = express();
const didit = new DiditClient({ webhookSecret: process.env.DIDIT_WEBHOOK_SECRET });

// Mount ONLY on the webhook route, before express.json() would otherwise consume the stream.
app.post("/webhooks/didit", createRawBodyMiddleware(), (req, res) => {
  try {
    const { event } = didit.webhooks.constructEvent(req.rawBody!, req.headers);

    if (event.webhook_type === "status.updated" && event.status === "Approved") {
      // event.decision has the full verification result
    }

    res.status(200).json({ received: true });
  } catch (error) {
    res.status(401).json({ error: "Invalid webhook" });
  }
});
```

Respond within 5 seconds with a `2xx` — queue any heavier work asynchronously. Didit retries
failed deliveries (non-2xx, timeout) roughly 1 and 4 minutes later, then gives up; retries and
fan-out to multiple destinations share the same `event_id` for idempotent processing.

### Any other framework

`createRawBodyMiddleware` is an Express convenience. On Fastify, Next.js Route Handlers, Hono,
etc., get the raw body however that framework provides it and pass it straight through:

```ts
// Next.js Route Handler
export async function POST(request: Request) {
  const rawBody = await request.text();
  const { event } = didit.webhooks.constructEvent(rawBody, Object.fromEntries(request.headers));
  // ...
  return Response.json({ received: true });
}
```

### Event types

| `webhook_type`               | Fires when                                              |
| ---------------------------- | ------------------------------------------------------- |
| `status.updated`             | A KYC/KYB session's status changes                      |
| `data.updated`               | Verification data corrected post-creation               |
| `user.status.updated`        | A user entity's status changes (ACTIVE/FLAGGED/BLOCKED) |
| `user.data.updated`          | A user entity's profile/metadata changes                |
| `business.status.updated`    | A business entity's status changes                      |
| `business.data.updated`      | A business entity's profile/metadata changes            |
| `transaction.created`        | A monitored transaction is created                      |
| `transaction.status.updated` | A transaction's status changes                          |
| `travel_rule.status.updated` | A Travel Rule exchange's status changes                 |

## Error handling

Every error thrown by this SDK extends `DiditError`, so one `catch` block is enough — branch
further with `instanceof` when you need to:

```ts
import { DiditAPIError, DiditRateLimitError, DiditError } from "didit-node-client";

try {
  await didit.sessions.create({ workflow_id: "wf_..." });
} catch (error) {
  if (error instanceof DiditRateLimitError) {
    console.log(`Rate limited, retry after ${error.retryAfter}s`);
  } else if (error instanceof DiditAPIError) {
    console.error(error.status, error.body); // structured API error
  } else if (error instanceof DiditError) {
    console.error(error.message); // config, validation, connection, or webhook error
  }
  throw error;
}
```

| Class                        | When                                                            |
| ---------------------------- | --------------------------------------------------------------- |
| `DiditConfigurationError`    | Missing/invalid client config (e.g. no API key)                 |
| `DiditInvalidRequestError`   | Invalid input caught client-side, before any network call       |
| `DiditConnectionError`       | Network failure, timeout, or aborted request                    |
| `DiditValidationError`       | `400` — request failed API-side validation                      |
| `DiditAuthenticationError`   | `401`/`403` — missing/invalid API key or insufficient scope     |
| `DiditNotFoundError`         | `404` — resource doesn't exist                                  |
| `DiditRateLimitError`        | `429` — carries `.retryAfter`, `.limit`, `.remaining`, `.reset` |
| `DiditServerError`           | `5xx` — problem on Didit's side                                 |
| `DiditWebhookSignatureError` | Webhook signature invalid, stale, or malformed                  |

`DiditAPIError` (the common base of the HTTP ones) also carries `.status`, `.body` (parsed API
error payload), `.headers`, `.request`, and `.requestId` for support/debugging.

## Retries, timeouts & rate limits

- `GET` requests (retrieve, list, generate PDF) automatically retry on network errors, `429`,
  and `5xx`, with exponential backoff + jitter, honoring `Retry-After`. Default `maxRetries: 2`.
- Mutating requests (`POST`/`PATCH`) are not retried automatically. Cancellation remains a typed `DiditConnectionError`, including cancellation during backoff.
- Every method accepts `{ signal, timeoutMs }` for cancellation and per-call timeout overrides:

  ```ts
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 5000);
  await didit.sessions.retrieve(id, { signal: controller.signal });
  ```

## TypeScript

Everything is exported — request payloads, response shapes, every decision feature, webhook
events:

```ts
import type {
  Session,
  SessionDecision,
  CreateSessionRequest,
  WebhookEvent,
  SessionWebhookEvent,
  IdVerificationResult,
  AmlScreeningResult,
} from "didit-node-client";
```

## Security best practices

- **Never** expose your API key client-side — call this SDK only from your backend.
- Always verify webhook signatures (`constructEvent` does this for you) instead of trusting
  the payload's `session_id`/`status` fields directly.
- Store `DIDIT_API_KEY` / `DIDIT_WEBHOOK_SECRET` in a secrets manager or environment variables,
  never in source control.
- Treat media URLs in decisions (portraits, document scans) as short-lived and sensitive — don't
  log or cache them beyond what you need.

## Examples

Runnable end-to-end scripts live in [`examples/`](./examples), covering hosted sessions,
webhooks, PDF reports, pagination, standalone verification, and KYB.

## Contributing

```bash
npm install
npm run build        # tsdown -> dist/ (CJS + ESM + types)
npm test             # jest
npm run lint         # Oxlint with TypeScript 7 type-aware rules
npm run typecheck    # tsc --noEmit
npm run verify       # everything above, what `prepublishOnly` runs
```

Issues and PRs welcome at the [GitHub repository](https://github.com/awaisjameel/didit-node-client).

## License

MIT © Awais Jameel
