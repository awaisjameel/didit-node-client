import type FormDataType from "form-data";
import { DiditInvalidRequestError } from "../errors";
import type { ImageInput } from "../types/id-verification";

const MAX_PORTRAIT_IMAGE_BYTES = 2 * 1024 * 1024;

/** Appends an {@link ImageInput} to a `form-data` instance under `field`. @internal */
export function appendImageField(form: FormDataType, field: string, input: ImageInput): void {
  if (Buffer.isBuffer(input)) {
    form.append(field, input, { filename: `${field}.jpg` });
    return;
  }

  if (isReadableStream(input)) {
    form.append(field, input, { filename: `${field}.jpg` });
    return;
  }

  if (typeof input === "object" && input !== null && "data" in input) {
    form.append(field, input.data, {
      filename: input.filename ?? `${field}.jpg`,
      contentType: input.contentType,
    });
    return;
  }

  throw new DiditInvalidRequestError(
    `\`${field}\` must be a Buffer, a readable stream, or { data, filename?, contentType? }.`,
  );
}

function isReadableStream(value: unknown): value is NodeJS.ReadableStream {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as NodeJS.ReadableStream).pipe === "function"
  );
}

/**
 * Normalizes `portrait_image` for `POST /v3/session/`, which expects a base64 string in the
 * JSON body. Accepts a `Buffer` for convenience and base64-encodes it automatically.
 * @internal
 */
export function normalizePortraitImage(value: string | Buffer | undefined): string | undefined {
  if (value === undefined) return undefined;

  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, "base64");
  if (bytes.byteLength > MAX_PORTRAIT_IMAGE_BYTES) {
    throw new DiditInvalidRequestError(
      `\`portrait_image\` must be at most 2MB, received ${(bytes.byteLength / (1024 * 1024)).toFixed(2)}MB.`,
    );
  }

  return Buffer.isBuffer(value) ? bytes.toString("base64") : value;
}
