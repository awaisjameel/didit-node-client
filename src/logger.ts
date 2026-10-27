/** A minimal logging function signature so consumers can plug in pino/winston/etc. */
export type DiditLogFn = (message: string, meta?: Record<string, unknown>) => void;

const REDACTED = "[REDACTED]";
const SENSITIVE_KEYS = new Set([
  "x-api-key",
  "apikey",
  "api_key",
  "authorization",
  "webhooksecret",
  "webhook_secret",
]);

/** Recursively redacts likely-sensitive keys before they hit a log sink. @internal */
export function redact(value: unknown, depth = 0): unknown {
  if (value === null || typeof value !== "object") return value;
  if (depth > 6) return REDACTED;
  if (Array.isArray(value)) return value.map((item) => redact(item, depth + 1));

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, val]) => [
      key,
      SENSITIVE_KEYS.has(key.toLowerCase()) ? REDACTED : redact(val, depth + 1),
    ]),
  );
}

/** Internal logger wrapper: no-ops unless `debug` is enabled, and always redacts secrets. */
export class Logger {
  constructor(
    private readonly enabled: boolean,
    private readonly sink: DiditLogFn = defaultSink,
  ) {}

  debug(message: string, meta?: Record<string, unknown>): void {
    if (!this.enabled) return;
    this.sink(message, meta ? (redact(meta) as Record<string, unknown>) : undefined);
  }
}

function defaultSink(message: string, meta?: Record<string, unknown>): void {
  // eslint-disable-next-line no-console
  console.log(`[didit] ${message}`, meta ?? "");
}
