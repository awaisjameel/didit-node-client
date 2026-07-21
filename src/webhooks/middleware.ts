import type { NextFunction, Request, RequestHandler, Response } from "express";

declare module "express-serve-static-core" {
  interface Request {
    rawBody?: Buffer;
  }
}

export interface RawBodyMiddlewareOptions {
  /** Rejects bodies larger than this many bytes with a 413. Default 5MB. */
  maxBytes?: number;
}

const DEFAULT_MAX_BYTES = 5 * 1024 * 1024;

/**
 * Express middleware that captures the exact raw request bytes onto `req.rawBody`, required
 * for webhook signature verification (re-stringifying a parsed body can change whitespace,
 * key order, or float formatting and invalidate the signature).
 *
 * Mount it **only** on your webhook route, before any body parser that would otherwise
 * consume the stream (e.g. `express.json()`):
 *
 * ```ts
 * app.post("/webhooks/didit", createRawBodyMiddleware(), (req, res) => {
 *   const { event } = client.webhooks.constructEvent(req.rawBody!, req.headers);
 *   res.sendStatus(200);
 * });
 * ```
 *
 * If you're on a framework other than Express (Fastify, Next.js, Hono, ...), read the raw
 * body yourself using whatever raw-body hook that framework provides and pass it straight to
 * `client.webhooks.constructEvent()` — this middleware is an Express-specific convenience.
 */
export function createRawBodyMiddleware(options: RawBodyMiddlewareOptions = {}): RequestHandler {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;

  return (req: Request, res: Response, next: NextFunction): void => {
    const chunks: Buffer[] = [];
    let receivedBytes = 0;
    let rejected = false;

    req.on("data", (chunk: Buffer) => {
      if (rejected) return;

      receivedBytes += chunk.length;
      if (receivedBytes > maxBytes) {
        rejected = true;
        res.status(413).json({ error: `Webhook body exceeds ${maxBytes} byte limit.` });
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      if (rejected) return;
      req.rawBody = Buffer.concat(chunks);
      next();
    });

    req.on("error", (err: Error) => {
      if (rejected) return;
      next(err);
    });
  };
}
