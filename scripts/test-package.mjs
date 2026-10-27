import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const temporaryRoot = path.resolve(os.tmpdir());
const temporary = await mkdtemp(path.join(temporaryRoot, "didit-package-test-"));
const npm = process.env.npm_execpath;
assert.ok(npm && path.isAbsolute(npm), "Run through npm run test:package.");

function run(args, cwd = root) {
  const result = spawnSync(process.execPath, args, { cwd, encoding: "utf8", windowsHide: true });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${args.join(" ")}\n${result.stdout}\n${result.stderr}`);
  return result.stdout;
}

try {
  const packResult = JSON.parse(
    run([npm, "pack", "--ignore-scripts", "--json", "--pack-destination", temporary]),
  );
  const [packed] = Array.isArray(packResult) ? packResult : Object.values(packResult);
  const manifest = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
  assert.equal(packed.version, manifest.version);
  const names = new Set(packed.files.map((file) => file.path));
  for (const filename of ["dist/index.js", "dist/index.mjs", "dist/index.d.ts", "dist/index.d.mts"])
    assert.ok(names.has(filename), `Missing packed ${filename}`);
  assert.ok(
    [...names].every(
      (name) =>
        !/^(node_modules|coverage|scripts|tests)\//.test(name) && !name.includes("/__tests__/"),
    ),
  );
  for (const mapFile of ["dist/index.d.ts.map", "dist/index.d.mts.map"]) {
    const map = JSON.parse(await readFile(path.join(root, mapFile), "utf8"));
    for (const source of map.sources)
      assert.ok(
        names.has(path.posix.normalize(path.posix.join("dist", source))),
        `Missing declaration source ${source}`,
      );
  }
  const typeCheck = `import express, { type RequestHandler } from "express";
import { DiditClient, createRawBodyMiddleware, type WebhookEvent } from "didit-node-client";
const handler: RequestHandler = createRawBodyMiddleware();
express().post("/webhook", handler, (req, res) => {
  const { event } = new DiditClient({ apiKey: "test", webhookSecret: "secret" }).webhooks.constructEvent(req.rawBody!, req.headers);
  if (event.webhook_type === "status.updated") res.json(event.decision?.id_verifications?.[0]?.full_name);
});
function decision(event: WebhookEvent): string | undefined | null {
  return event.webhook_type === "status.updated" ? event.decision?.id_verifications?.[0]?.full_name : undefined;
}
void decision;
`;
  for (const major of [4, 5]) {
    const consumer = path.join(temporary, `express-${major}`);
    await mkdir(consumer);
    await writeFile(
      path.join(consumer, "package.json"),
      JSON.stringify({
        private: true,
        dependencies: {
          "didit-node-client": `file:${path.join(temporary, packed.filename).replaceAll("\\", "/")}`,
          express: major === 4 ? "^4.22.3" : "^5.3.0",
          "@types/express": major === 4 ? "^4.17.25" : "^5.0.6",
        },
      }),
    );
    run([npm, "install", "--ignore-scripts", "--omit=dev", "--no-fund", "--no-audit"], consumer);
    await cp(path.join(root, "tests/consumer-smoke.mjs"), path.join(consumer, "smoke.mjs"));
    for (const extension of ["cts", "mts"])
      await writeFile(path.join(consumer, `types.${extension}`), typeCheck);
    run(
      [
        path.join(root, "node_modules/typescript/bin/tsc"),
        "--noEmit",
        "--strict",
        "--module",
        "NodeNext",
        "--moduleResolution",
        "NodeNext",
        "--target",
        "ES2022",
        "--esModuleInterop",
        "types.cts",
        "types.mts",
      ],
      consumer,
    );
    console.log(run(["smoke.mjs"], consumer).trim());
    run([npm, "audit", "--omit=dev"], consumer);
    console.log(
      `Packed ${packed.version}: Express ${major}, CJS/ESM, strict declarations and production dependency audit pass.`,
    );
  }
} finally {
  assert.equal(path.dirname(path.resolve(temporary)), temporaryRoot);
  assert.ok(path.basename(temporary).startsWith("didit-package-test-"));
  await rm(temporary, { recursive: true, force: true });
}
