/**
 * Flattens a params object for the HTTP layer: arrays become comma-separated strings (the
 * form Didit's filters expect, e.g. `status=Approved,In Review`), booleans/numbers become
 * strings, and `undefined`/`null` values are dropped.
 * @internal
 */
export function toQueryParams<T extends object>(
  params: T | undefined,
): Record<string, string | number | boolean | undefined> {
  if (!params) return {};

  const result: Record<string, string | number | boolean | undefined> = {};
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      result[key] = value.join(",");
    } else if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean"
    ) {
      result[key] = value;
    }
  }
  return result;
}
