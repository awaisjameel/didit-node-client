/**
 * Deterministic JSON serialization used for the `X-Signature-V2` webhook scheme: object keys
 * are sorted recursively (arrays keep their order) and non-ASCII characters are left
 * unescaped, matching `JSON.stringify`'s default behavior in Node.
 *
 * Serialize entries directly: JSON.stringify(object) reorders numeric keys, and
 * copying into an ordinary object can discard an own __proto__ key. JavaScript
 * already serializes whole-valued numbers as integers, matching shorten_floats.
 * @internal
 */
export function canonicalJsonStringify(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJsonStringify).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort((left, right) =>
      Buffer.compare(Buffer.from(left), Buffer.from(right)),
    );
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJsonStringify(record[key])}`).join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError("Expected a JSON value.");
  return encoded;
}
