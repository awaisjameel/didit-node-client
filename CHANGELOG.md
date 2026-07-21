# Changelog

All notable changes to this project are documented in this file. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
[Semantic Versioning](https://semver.org/).

## 2.0.0

Complete rewrite against Didit's current **v3** Verification API. Didit's own platform moved
from v1 (OAuth2 `client_id`/`client_secret`, string `features`) to v3 (long-lived `x-api-key`,
`workflow_id`-based sessions, KYB support, restructured decision payloads) — this release
follows that migration end to end. See [MIGRATION.md](./MIGRATION.md) for the full upgrade guide.

### Breaking changes

- Authentication switched from OAuth2 (`clientId`/`clientSecret`) to a single `apiKey`
  (`x-api-key` header). `authUrl`, `tokenExpiryBuffer`, and `getAccessToken()` are gone.
- `DiDiTClient` renamed to `DiditClient`; every method moved under resource namespaces
  (`.sessions`, `.idVerification`, `.webhooks`).
- `createSession(callback, vendorData, options)` → `sessions.create({ workflow_id, ... })`;
  the `features` string param is replaced by workflow-driven configuration.
- `getSession`/`updateSessionStatus`/`generateSessionPDF` renamed to
  `sessions.retrieve`/`sessions.updateStatus`/`sessions.generatePdf`.
- The session decision payload changed from a fixed `{ kyc, aml, face, location }` shape to
  per-feature arrays (`id_verifications`, `aml_screenings`, `face_matches`, ...).
- `verifyWebhookSignature`/`processWebhook` replaced by `webhooks.constructEvent(rawBody, headers)`
  (note the swapped argument order), verifying Didit's three current signature schemes.
- Errors are now a typed class hierarchy (`DiditAPIError`, `DiditRateLimitError`, ...) instead
  of a single `Error` with ad hoc properties.
- Minimum Node.js version raised from 16 to **18**.
- Package output moved from `lib/` (CJS-only) to `dist/` (dual CJS + ESM + type declarations).

### Added

- `sessions.list()` / `sessions.listAll()` — filtered and auto-paginating session listing.
- `sessions.updateData()`, `sessions.updatePoaData()`, `sessions.updateKybCompanyData()` —
  correct OCR/registry-extracted fields post-verification.
- `idVerification.verify()` — standalone document verification without a hosted session.
- KYB (business verification) support throughout the Sessions API.
- Automatic retries with exponential backoff + jitter for safe requests, honoring `Retry-After`.
- Full `AbortSignal` / per-call timeout support on every method.
- Debug logging with automatic secret redaction.
- Comprehensive typed error hierarchy with parsed rate-limit details.

### Fixed

- The Express raw-body middleware concatenated request chunks via string coercion, which could
  corrupt multi-byte UTF-8 characters split across TCP chunk boundaries; it now concatenates
  `Buffer`s and decodes once. It also now enforces a configurable body-size limit.
- PDF/error responses returned as `arraybuffer` are now correctly decoded as JSON when the API
  returns an error body instead of a PDF (previously surfaced as an opaque binary error).

## 1.0.4 and earlier

Client for Didit's legacy v1 API (OAuth2 `client_id`/`client_secret`, `features` string,
`{ kyc, aml, face, location }` decision shape). Superseded by 2.0.0 above.
