import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import { createRequire } from "node:module";
import express from "express";
import * as esm from "didit-node-client";

const require = createRequire(import.meta.url);
const cjs = require("didit-node-client");
const secret = "consumer-webhook-secret";
const sign = (body) => crypto.createHmac("sha256", secret).update(body).digest("hex");
const received = [];
const api = http.createServer(async (request, response) => {
  try {
    assert.equal(request.headers["x-api-key"], "consumer-api-key");
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    received.push({ url: request.url, method: request.method });
    response.setHeader("Content-Type", "application/json");
    if (request.url === "/v3/session/") {
      assert.equal(JSON.parse(body).vendor_data, "0");
      response
        .writeHead(201)
        .end(JSON.stringify({ session_id: "consumer-session", status: "Not Started" }));
    } else if (request.url === "/v3/id-verification/") {
      assert.match(request.headers["content-type"], /^multipart\/form-data; boundary=/);
      assert.ok(body.includes(Buffer.from([0, 255, 1, 128, 2])));
      assert.ok(body.includes(Buffer.from('name="critical_field_occlusion_action"')));
      response.end(
        JSON.stringify({ request_id: "verification", id_verification: { status: "Approved" } }),
      );
    } else if (request.url.endsWith("/generate-pdf/")) {
      assert.equal(request.headers.accept, "application/pdf");
      response.setHeader("Content-Type", "application/pdf");
      response.end("%PDF-1.7\nconsumer fixture");
    } else if (request.url.includes("/redirect/")) {
      response.writeHead(302, { Location: "/credential-leak" }).end();
    } else if (request.url === "/v3/session/s%20%2F1/decision/") {
      response.end(JSON.stringify({ session_id: "s /1", status: "Approved" }));
    } else {
      response.writeHead(404).end(JSON.stringify({ detail: "Unexpected route" }));
    }
  } catch (error) {
    response.writeHead(500).end(JSON.stringify({ detail: error.message }));
  }
});

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

const baseUrl = await listen(api);
const servers = [api];
try {
  for (const [label, sdk] of [
    ["ESM", esm],
    ["CJS", cjs],
  ]) {
    const client = new sdk.DiditClient({
      apiKey: "consumer-api-key",
      webhookSecret: secret,
      baseUrl,
      maxRetries: 0,
    });
    assert.equal(
      (await client.sessions.create({ workflow_id: "workflow", vendor_data: "0" })).session_id,
      "consumer-session",
    );
    assert.equal((await client.sessions.retrieve("s /1")).status, "Approved");
    assert.ok(
      (await client.sessions.generatePdf("consumer-session"))
        .subarray(0, 4)
        .equals(Buffer.from("%PDF")),
    );
    assert.equal(
      (
        await client.idVerification.verify({
          front_image: Buffer.from([0, 255, 1, 128, 2]),
          critical_field_occlusion_action: "DECLINE",
        })
      ).id_verification.status,
      "Approved",
    );
    await assert.rejects(
      client.sessions.retrieve("redirect"),
      (error) => error instanceof sdk.DiditAPIError && error.status === 302,
    );

    const app = express();
    app.post("/webhook", sdk.createRawBodyMiddleware({ maxBytes: 1024 }), (req, res) => {
      try {
        const { event } = client.webhooks.constructEvent(req.rawBody, req.headers);
        res.json({ status: event.status, name: event.metadata?.name });
      } catch {
        res.sendStatus(401);
      }
    });
    app.use(express.json());
    const server = http.createServer(app);
    servers.push(server);
    const url = `${await listen(server)}/webhook`;
    const body = JSON.stringify({
      timestamp: Math.floor(Date.now() / 1000),
      status: "Approved",
      metadata: { name: "José 日本語" },
    });
    const valid = await fetch(url, {
      method: "POST",
      body,
      headers: { "x-signature": sign(body), "content-type": "application/json" },
    });
    assert.equal(valid.status, 200);
    assert.deepEqual(await valid.json(), { status: "Approved", name: "José 日本語" });
    assert.equal(
      (
        await fetch(url, {
          method: "POST",
          body: body.replace("Approved", "Declined"),
          headers: { "x-signature": sign(body) },
        })
      ).status,
      401,
    );
    const stale = JSON.stringify({ timestamp: Math.floor(Date.now() / 1000) - 600 });
    assert.equal(
      (
        await fetch(url, {
          method: "POST",
          body: stale,
          headers: {
            "x-signature": sign(stale),
            "x-timestamp": String(Math.floor(Date.now() / 1000)),
          },
        })
      ).status,
      401,
    );
    assert.equal((await fetch(url, { method: "POST", body: "x".repeat(2048) })).status, 413);
    console.log(
      `${label}: actual HTTP JSON/multipart/PDF transport, redirects, Express webhooks, tamper/replay rejection and size limits pass.`,
    );
  }
  assert.ok(received.every((request) => request.url !== "/credential-leak"));
} finally {
  await Promise.all(
    servers.map(
      (server) =>
        new Promise((resolve, reject) => {
          server.close((error) => (error ? reject(error) : resolve()));
          server.closeAllConnections();
        }),
    ),
  );
}
