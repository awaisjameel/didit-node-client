import { EventEmitter } from "node:events";
import type { Request } from "express";
import { createRawBodyMiddleware } from "../../webhooks/middleware";

function fakeRequest(): EventEmitter & Request {
  return new EventEmitter() as EventEmitter & Request;
}

function fakeResponse() {
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(payload: unknown) {
      res.body = payload;
      return res;
    },
  };
  return res;
}

describe("createRawBodyMiddleware", () => {
  it.each([NaN, Infinity, 0, -1, 1.5])("rejects invalid byte limit %s", (maxBytes) => {
    expect(() => createRawBodyMiddleware({ maxBytes })).toThrow(/maxBytes/);
  });

  it("forwards a stream failure once and never resumes processing", () => {
    const req = fakeRequest();
    const next = jest.fn();
    createRawBodyMiddleware()(req as never, fakeResponse() as never, next);
    const error = new Error("stream failed");
    req.emit("error", error);
    req.emit("end");
    expect(next).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledWith(error);
    expect(req.rawBody).toBeUndefined();
  });
  it("concatenates chunks into an exact Buffer without corrupting multi-byte UTF-8 split across chunks", () => {
    const payload = JSON.stringify({ name: "José 日本語 emoji: 🎉" });
    const fullBuffer = Buffer.from(payload, "utf8");
    // Split at an arbitrary byte offset that lands inside a multi-byte sequence.
    const splitAt = 12;
    const chunk1 = fullBuffer.subarray(0, splitAt);
    const chunk2 = fullBuffer.subarray(splitAt);

    const req = fakeRequest();
    const res = fakeResponse();
    const next = jest.fn();
    const middleware = createRawBodyMiddleware();

    middleware(req as never, res as never, next);
    req.emit("data", chunk1);
    req.emit("data", chunk2);
    req.emit("end");

    expect(next).toHaveBeenCalledTimes(1);
    expect(req.rawBody).toEqual(fullBuffer);
    expect(req.rawBody!.toString("utf8")).toBe(payload);
  });

  it("rejects bodies larger than maxBytes with a 413 and does not call next()", () => {
    const req = fakeRequest();
    const res = fakeResponse();
    const next = jest.fn();
    const middleware = createRawBodyMiddleware({ maxBytes: 10 });

    middleware(req as never, res as never, next);
    req.emit("data", Buffer.from("this is definitely more than ten bytes"));
    req.emit("end");

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(413);
  });

  it("forwards stream errors to next(err)", () => {
    const req = fakeRequest();
    const res = fakeResponse();
    const next = jest.fn();
    const middleware = createRawBodyMiddleware();
    const error = new Error("stream exploded");

    middleware(req as never, res as never, next);
    req.emit("error", error);

    expect(next).toHaveBeenCalledWith(error);
  });

  it("produces an empty Buffer for an empty body instead of leaving rawBody undefined", () => {
    const req = fakeRequest();
    const res = fakeResponse();
    const next = jest.fn();
    const middleware = createRawBodyMiddleware();

    middleware(req as never, res as never, next);
    req.emit("end");

    expect(req.rawBody).toEqual(Buffer.alloc(0));
    expect(next).toHaveBeenCalledTimes(1);
  });
});
