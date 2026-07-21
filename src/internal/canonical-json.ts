/**
 * Deterministic JSON serialization used for the `X-Signature-V2` webhook scheme: object keys
 * are sorted recursively (arrays keep their order) and non-ASCII characters are left
 * unescaped, matching `JSON.stringify`'s default behavior in Node.
 *
 * Didit's own reference implementation additionally runs a `shortenFloats` normalization
 * step before serializing, whose exact rounding rules aren't published. This function does
 * not attempt to replicate it, so V2 verification is best-effort: {@link verifyWebhookSignature}
 * always also checks the raw-body (`X-Signature`) and envelope (`X-Signature-Simple`) schemes
 * when their headers are present, and accepts the payload if *any* scheme validates — so an
 * imperfect V2 match never causes a false rejection as long as another header is available.
 * @internal
 */
export function canonicalJsonStringify(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value === null || typeof value !== "object") return value;

  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    sorted[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
  }
  return sorted;
}
