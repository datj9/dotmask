import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { parseCompleteHttpRequest, sanitizeRequestBody } from "../dist/proxy/http.js";

describe("parseCompleteHttpRequest", () => {
  test("parses content-length request with UTF-8 body without corruption", () => {
    const json = JSON.stringify({ text: "xin chao 👋 你好" });
    const body = Buffer.from(json, "utf8");
    const request = Buffer.concat([
      Buffer.from(
        `POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n`,
        "latin1",
      ),
      body,
    ]);

    const parsed = parseCompleteHttpRequest(request);
    assert.ok(parsed);
    assert.equal(parsed.requestLine, "POST /v1/messages HTTP/1.1");
    assert.equal(parsed.headers.host, "api.anthropic.com");
    assert.equal(parsed.body.toString("utf8"), json);
    assert.equal(parsed.bytesConsumed, request.length);
  });

  test("returns null for incomplete content-length body", () => {
    const partial = Buffer.from(
      "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\nabc",
      "latin1",
    );

    assert.equal(parseCompleteHttpRequest(partial), null);
  });

  test("parses complete chunked request body", () => {
    const chunkedBody = Buffer.from("d\r\nhello, world!\r\n0\r\n\r\n", "latin1");
    const request = Buffer.concat([
      Buffer.from(
        "POST /chunked HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        "latin1",
      ),
      chunkedBody,
    ]);

    const parsed = parseCompleteHttpRequest(request);
    assert.ok(parsed);
    assert.equal(parsed.body.toString("utf8"), "hello, world!");
    assert.equal(parsed.bytesConsumed, request.length);
  });

  test("returns null for incomplete chunked request body", () => {
    const partial = Buffer.concat([
      Buffer.from(
        "POST /chunked HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        "latin1",
      ),
      Buffer.from("5\r\nhello\r\n0\r\n", "latin1"),
    ]);

    assert.equal(parseCompleteHttpRequest(partial), null);
  });

  test("reports bytes consumed so pipelined requests can be preserved", () => {
    const first = Buffer.from("GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n", "latin1");
    const second = Buffer.from("GET /two HTTP/1.1\r\nHost: example.com\r\n\r\n", "latin1");
    const combined = Buffer.concat([first, second]);

    const parsed = parseCompleteHttpRequest(combined);
    assert.ok(parsed);
    assert.equal(parsed.requestLine, "GET /one HTTP/1.1");
    assert.equal(parsed.bytesConsumed, first.length);
    assert.equal(combined.subarray(parsed.bytesConsumed).toString("latin1"), second.toString("latin1"));
  });

  test("rejects ambiguous content-length plus transfer-encoding framing", () => {
    const request = Buffer.from(
      "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
      "latin1",
    );
    assert.throws(() => parseCompleteHttpRequest(request), /ambiguous request framing/);
  });

  test("rejects duplicate headers", () => {
    const request = Buffer.from(
      "GET / HTTP/1.1\r\nHost: example.com\r\nHost: attacker.example\r\n\r\n",
      "latin1",
    );
    assert.throws(() => parseCompleteHttpRequest(request), /duplicate request header/);
  });
});

describe("sanitizeRequestBody", () => {
  test("recursively masks secrets in arbitrary JSON properties", () => {
    const real = "correct horse battery staple";
    const input = Buffer.from(JSON.stringify({ messages: [{ metadata: { password: real } }] }));
    const result = sanitizeRequestBody(input, "application/json", "");
    const parsed = JSON.parse(result.body.toString("utf8"));

    assert.equal(result.count, 1);
    assert.notEqual(parsed.messages[0].metadata.password, real);
    assert.equal(parsed.messages[0].metadata.password.length, real.length);
  });

  test("blocks malformed JSON instead of forwarding it", () => {
    assert.throws(
      () => sanitizeRequestBody(Buffer.from("{invalid"), "application/json", ""),
      /invalid JSON request body/,
    );
  });

  test("blocks compressed and binary request bodies", () => {
    assert.throws(
      () => sanitizeRequestBody(Buffer.from("payload"), "application/json", "gzip"),
      /unsupported request content-encoding/,
    );
    assert.throws(
      () => sanitizeRequestBody(Buffer.from([0, 1, 2]), "application/octet-stream", ""),
      /unsupported request content-type/,
    );
  });

  test("masks secrets in textual non-JSON bodies", () => {
    const real = "sk-proj-abcdefghijklmnopqrstuvwxyz12345";
    const result = sanitizeRequestBody(Buffer.from(`token=${real}`), "text/plain", "");
    assert.equal(result.count, 1);
    assert.ok(!result.body.toString("utf8").includes(real));
  });
});
