const BASE_DELAY_MS = 300;
const MAX_DELAY_MS = 8_000;

/**
 * Computes an exponential-backoff delay with jitter for retry `attempt` (0-indexed).
 * Honors a server-provided `Retry-After` value (seconds, or an HTTP-date string) when present.
 * @internal
 */
export function computeBackoffDelayMs(attempt: number, retryAfterHeader?: string | null): number {
  if (retryAfterHeader) {
    const seconds = Number(retryAfterHeader);
    if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);

    const dateMs = Date.parse(retryAfterHeader);
    if (!Number.isNaN(dateMs)) return Math.max(0, dateMs - Date.now());
  }

  const exponential = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** attempt);
  const jitter = Math.random() * exponential * 0.25;
  return Math.round(exponential * 0.75 + jitter);
}

/** @internal */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason);
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
