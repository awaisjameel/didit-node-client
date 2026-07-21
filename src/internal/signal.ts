/**
 * Merges a timeout signal with an optional caller-provided signal, without relying on
 * `AbortSignal.any` (added in Node 20.3 — this package supports Node 18+).
 * @internal
 */
export function mergeSignals(...signals: Array<AbortSignal | undefined>): AbortSignal {
  const controller = new AbortController();
  const present = signals.filter((signal): signal is AbortSignal => signal !== undefined);

  for (const signal of present) {
    if (signal.aborted) {
      controller.abort(signal.reason);
      break;
    }
    signal.addEventListener(
      "abort",
      () => {
        if (!controller.signal.aborted) controller.abort(signal.reason);
      },
      { once: true },
    );
  }

  return controller.signal;
}
