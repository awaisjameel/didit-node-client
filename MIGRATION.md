# Migrating from 2.x to 3.0

- Use maintained Node 22, 24 or 26. Minimum supported patches are 22.18.0 and 24.11.0; development uses the latest patch on each line.
- Webhooks must carry a full-payload V2 or raw-body signature. Deprecated Simple-only signatures no longer authenticate events; `verifiedWith` is now `"v2" | "raw"`.
- Freshness comes from the signed body timestamp. A supplied `X-Timestamp` must match it; refreshing only the header cannot replay an expired body. Legacy signed Unix/ISO `created_at` remains supported.
- `X-Signature-V2-Previous` and `X-Signature-Previous` support Didit's destination-secret rotation window. The unsigned `isTest` hint never changes authentication requirements.
- Webhook events narrow by `webhook_type`; `resubmit_info` is an object with `nodes_to_resubmit` and `reasons`. Transaction amounts are decimal strings. Decision arrays and several decision fields may be null; `session_kind` is optional on create responses.
- `listAll({ session_kind: "all" })` paginates KYC and KYB independently. It yields all KYC records before KYB records. Page limits and offsets must be safe integers within their documented ranges.
- HTTP redirects and malformed successful JSON/PDF responses raise package errors. Cancellation during retries remains `DiditConnectionError`.
- Contributors: TypeScript 7 replaces TypeScript 5; SWC replaces ts-jest, Oxlint plus tsgolint replaces ESLint, and tsdown replaces tsup. `npm run verify` includes type-aware linting, formatting, tests, declaration generation, and CJS/ESM builds. The public runtime entry points remain unchanged.

---

# Migrating from 1.x to 2.0

Didit's API itself changed from **v1** (what 1.x wrapped) to **v3** — a different auth model,
different session shape, and a completely restructured decision payload. This release is a
ground-up rewrite to match it; there is no compatibility shim, because the underlying v1 API
this package's 1.x version talked to no longer reflects Didit's current platform.

## 1. Authentication: `clientId`/`clientSecret` → `apiKey`

v1 used OAuth2 `client_credentials` (`clientId` + `clientSecret` → short-lived bearer token,
auto-refreshed by the client). v3 uses a single long-lived API key sent as `x-api-key` — there
is no token endpoint, no expiry, and no `getAccessToken()` anymore.

```diff
- const client = new DiDiTClient({
-   clientId: process.env.DIDIT_CLIENT_ID,
-   clientSecret: process.env.DIDIT_CLIENT_SECRET,
-   authUrl: "https://apx.didit.me",
- });
+ const didit = new DiditClient({
+   apiKey: process.env.DIDIT_API_KEY,
+ });
```

Generate an API key in the Business Console under Settings → API Keys. `authUrl` and
`tokenExpiryBuffer` no longer exist (there's no separate auth host or token to expire).

## 2. Client class renamed

`DiDiTClient` → `DiditClient`. Every method on it changed shape (see below), so there is no
value in keeping the old name as an alias — treat this as a new client.

## 3. Sessions moved under `.sessions`, and `features` → `workflow_id`

v1 sessions took a `features` string (`"OCR + NFC + FACE"`). v3 sessions run a **workflow** you
build once in the console (KYC or KYB, with whatever steps you configure) and reference by
`workflow_id` — the feature list lives in the workflow now, not the API call.

```diff
- const session = await client.createSession(
-   "https://example.com/callback",
-   "vendor-data-123",
-   { features: "OCR + NFC + FACE" },
- );
+ const session = await didit.sessions.create({
+   workflow_id: "wf_...",
+   vendor_data: "vendor-data-123",
+   callback: "https://example.com/callback",
+ });
```

| 1.x                                               | 2.0                                                                            |
| ------------------------------------------------- | ------------------------------------------------------------------------------ |
| `client.createSession(cb, vd, opts)`              | `didit.sessions.create({ workflow_id, vendor_data, callback })`                |
| `client.getSession(id)`                           | `didit.sessions.retrieve(id)`                                                  |
| `client.updateSessionStatus(id, status, comment)` | `didit.sessions.updateStatus(id, { new_status, comment })`                     |
| `client.generateSessionPDF(id)`                   | `didit.sessions.generatePdf(id)`                                               |
| _(none)_                                          | `didit.sessions.list(params)` / `.listAll(params)` — new                       |
| _(none)_                                          | `didit.sessions.updateData` / `.updatePoaData` / `.updateKybCompanyData` — new |
| _(none)_                                          | `didit.idVerification.verify(...)` — new, standalone document check            |

`updateStatus`'s `new_status` also now accepts `"Resubmitted"` in addition to
`"Approved"`/`"Declined"`, with an optional `nodes_to_resubmit` list.

## 4. The decision payload is fully restructured

v1 returned a fixed `{ kyc, aml, face, location }` shape. v3 returns **arrays per feature**,
since a workflow can run a feature more than once or not at all:

```diff
- decision.kyc?.full_name
- decision.kyc?.document_type
- decision.aml?.hits
- decision.face?.face_match_similarity
- decision.location?.ip_country
+ decision.id_verifications?.[0]?.full_name
+ decision.id_verifications?.[0]?.document_type
+ decision.aml_screenings?.[0]?.hits
+ decision.face_matches?.[0]?.score
+ decision.ip_analyses?.[0]?.ip_country
```

New feature arrays with no v1 equivalent: `nfc_verifications`, `liveness_checks` (split out from
what v1 called `face`), `phone_verifications`, `email_verifications`, `poa_verifications`,
`database_validations`, `document_ai_documents`, questionnaire responses, and — for KYB —
`registry_checks`, `document_verifications`, `key_people_checks`.

## 5. Webhooks: three signature headers instead of one

v1 sent a single `X-Signature` (HMAC-SHA256 over the raw body). v3 sends up to three
(`X-Signature-V2`, `X-Signature`, `X-Signature-Simple`) for resilience against proxies that
reformat the body before your handler sees it.

```diff
- const payload = client.processWebhook(req); // required req.rawBody as a string
+ const { event } = didit.webhooks.constructEvent(req.rawBody, req.headers); // string OR Buffer
```

- `verifyWebhookSignature(headers, rawBody)` → `didit.webhooks.constructEvent(rawBody, headers)`
  (**argument order swapped** — body first, to match `rawBody` often being read asynchronously).
- `processWebhook(req)` is gone; call `constructEvent` directly with `req.rawBody` and
  `req.headers`.
- `createRawBodyMiddleware()` still exists and is still mounted the same way, but now
  concatenates chunks as `Buffer`s internally (the 1.x version had a latent bug where
  multi-byte UTF-8 characters split across TCP chunk boundaries could be corrupted) and adds a
  configurable `maxBytes` limit (default 5MB).
- The parsed payload's shape changed to match v3's envelope — see
  [Event types](./README.md#event-types) in the README.

## 6. Config & environment variables

| 1.x                    | 2.0                                |
| ---------------------- | ---------------------------------- |
| `DIDIT_CLIENT_ID`      | _(removed)_                        |
| `DIDIT_CLIENT_SECRET`  | _(removed)_                        |
| `DIDIT_AUTH_URL`       | _(removed)_                        |
| _(none)_               | `DIDIT_API_KEY` — new              |
| `DIDIT_WEBHOOK_SECRET` | `DIDIT_WEBHOOK_SECRET` — unchanged |
| `DIDIT_BASE_URL`       | `DIDIT_BASE_URL` — unchanged       |
| `tokenExpiryBuffer`    | _(removed — no tokens)_            |

## 7. Errors are now typed classes

1.x threw a single `Error` with `.context`, `.originalError`, `.response` bolted on. 2.0 throws
a proper hierarchy (`DiditAPIError`, `DiditRateLimitError`, `DiditValidationError`, ...) — see
[Error handling](./README.md#error-handling) in the README.

## 8. Runtime requirements

Node.js **16+** → **18+**. `axios` bumped to 1.8.x; the unused `buffer` polyfill dependency was
dropped (this is a Node-only package — the global `Buffer` is always available).

---

Still stuck? Open an issue at
[github.com/awaisjameel/didit-node-client/issues](https://github.com/awaisjameel/didit-node-client/issues).
