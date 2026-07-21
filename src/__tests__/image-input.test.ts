import FormData from "form-data";
import { appendImageField, normalizePortraitImage } from "../internal/image-input";
import { DiditInvalidRequestError } from "../errors";

describe("appendImageField", () => {
  it("accepts a Buffer", () => {
    const form = new FormData();
    expect(() => appendImageField(form, "front_image", Buffer.from("bytes"))).not.toThrow();
  });

  it("accepts a { data, filename, contentType } descriptor", () => {
    const form = new FormData();
    expect(() =>
      appendImageField(form, "front_image", {
        data: Buffer.from("bytes"),
        filename: "id.png",
        contentType: "image/png",
      }),
    ).not.toThrow();
  });

  it("rejects unsupported input types", () => {
    const form = new FormData();
    expect(() => appendImageField(form, "front_image", "not-a-buffer" as never)).toThrow(
      DiditInvalidRequestError,
    );
  });
});

describe("normalizePortraitImage", () => {
  it("passes a string through unchanged (already base64)", () => {
    expect(normalizePortraitImage("already-base64")).toBe("already-base64");
  });

  it("returns undefined for undefined input", () => {
    expect(normalizePortraitImage(undefined)).toBeUndefined();
  });

  it("base64-encodes a Buffer", () => {
    const buffer = Buffer.from("hello world");
    expect(normalizePortraitImage(buffer)).toBe(buffer.toString("base64"));
  });

  it("rejects a Buffer larger than 2MB", () => {
    const oversized = Buffer.alloc(2 * 1024 * 1024 + 1);
    expect(() => normalizePortraitImage(oversized)).toThrow(DiditInvalidRequestError);
  });

  it("rejects base64 strings larger than 2MB after decoding", () => {
    const encoded = Buffer.alloc(2 * 1024 * 1024 + 1).toString("base64");
    expect(() => normalizePortraitImage(encoded)).toThrow(DiditInvalidRequestError);
  });

  it("accepts a Buffer exactly at the 2MB boundary", () => {
    const boundary = Buffer.alloc(2 * 1024 * 1024);
    expect(() => normalizePortraitImage(boundary)).not.toThrow();
  });
});
