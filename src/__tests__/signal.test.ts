import { mergeSignals } from "../internal/signal";

describe("mergeSignals", () => {
  it("returns a non-aborted signal when no input signals are aborted", () => {
    const merged = mergeSignals(new AbortController().signal, undefined);
    expect(merged.aborted).toBe(false);
  });

  it("returns an already-aborted signal if any input is already aborted", () => {
    const aborted = new AbortController();
    aborted.abort(new Error("already gone"));
    const merged = mergeSignals(undefined, aborted.signal);
    expect(merged.aborted).toBe(true);
  });

  it("propagates a later abort from any source signal", () => {
    const a = new AbortController();
    const b = new AbortController();
    const merged = mergeSignals(a.signal, b.signal);

    expect(merged.aborted).toBe(false);
    b.abort(new Error("b aborted"));
    expect(merged.aborted).toBe(true);
  });

  it("works with zero signals", () => {
    const merged = mergeSignals();
    expect(merged.aborted).toBe(false);
  });
});
