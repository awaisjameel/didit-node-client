# Examples

Runnable scripts demonstrating common integrations. Each is a plain Node.js script — no build
step required.

| File | Demonstrates |
| --- | --- |
| [`basic-verification.js`](./basic-verification.js) | Create a session, retrieve its decision |
| [`webhook-server.js`](./webhook-server.js) | Express webhook receiver with signature verification |
| [`express-integration/index.js`](./express-integration/index.js) | Full Express app: create, retrieve, webhook, PDF |
| [`pdf-report.js`](./pdf-report.js) | Generate and save a compliance PDF report |
| [`list-sessions.js`](./list-sessions.js) | Filtering and auto-paginating through sessions |
| [`standalone-id-verification.js`](./standalone-id-verification.js) | One-shot document check without a hosted session |
| [`kyb-verification.js`](./kyb-verification.js) | Business (KYB) verification session |

## Setup

```bash
npm install didit-node-client express dotenv
```

Create a `.env` file next to the script you're running:

```bash
DIDIT_API_KEY=your_api_key
DIDIT_WORKFLOW_ID=your_workflow_id
DIDIT_WEBHOOK_SECRET=your_webhook_secret   # only needed for webhook-server.js
```

Then run any example directly, e.g.:

```bash
node examples/basic-verification.js
```
