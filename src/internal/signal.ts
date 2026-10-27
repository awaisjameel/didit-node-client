/**
 * Compose cancellation using the native API available in every supported Node runtime.
 * @internal
 */
export function mergeSignals(...signals: Array<AbortSignal | undefined>): AbortSignal {
  const present = signals.filter((signal): signal is AbortSignal => signal !== undefined);
  return AbortSignal.any(present);
}
