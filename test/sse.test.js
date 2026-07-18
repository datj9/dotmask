import { describe, test } from "node:test";
import assert from "node:assert/strict";
import {
  decodeChunked,
  encodeChunkedPayload,
  getCompleteChunkedMessageLength,
  IncrementalChunkedBodyParser,
  rawBytesHaveTerminal,
  stripChunkSizeLines,
  TERMINAL_CHUNK,
} from "../dist/proxy/sse.js";

describe("chunked HTTP helpers", () => {
  test("encodes and decodes multiple payloads", () => {
    const wire = Buffer.concat([
      encodeChunkedPayload("hello"),
      encodeChunkedPayload(" world"),
      TERMINAL_CHUNK,
    ]);
    assert.equal(decodeChunked(wire).toString("utf8"), "hello world");
    assert.equal(getCompleteChunkedMessageLength(wire), wire.length);
  });

  test("supports chunk extensions and trailers", () => {
    const wire = Buffer.from("5;foo=bar\r\nhello\r\n0\r\nX-Test: yes\r\n\r\n", "latin1");
    assert.equal(decodeChunked(wire).toString("utf8"), "hello");
    assert.equal(getCompleteChunkedMessageLength(wire), wire.length);
  });

  test("returns null for incomplete wire data", () => {
    assert.equal(getCompleteChunkedMessageLength(Buffer.from("5\r\nhel", "latin1")), null);
    assert.equal(getCompleteChunkedMessageLength(Buffer.from("0\r\n", "latin1")), null);
  });

  test("rejects malformed sizes and terminators", () => {
    assert.throws(() => getCompleteChunkedMessageLength(Buffer.from("nope\r\n", "latin1")), /invalid chunk size/);
    assert.throws(() => decodeChunked(Buffer.from("5\r\nhelloXX", "latin1")), /invalid chunk payload terminator/);
  });

  test("incrementally parses payloads and terminal chunk", () => {
    const parser = new IncrementalChunkedBodyParser();
    assert.deepEqual(parser.push(Buffer.from("5\r\nhel", "latin1")), { payloads: [], terminal: false });
    const result = parser.push(Buffer.from("lo\r\n0\r\n\r\n", "latin1"));
    assert.equal(result.payloads.length, 1);
    assert.equal(result.payloads[0].toString("utf8"), "hello");
    assert.equal(result.terminal, true);
  });

  test("detects and strips terminal chunk lines", () => {
    const text = "5\r\nhello\r\n0\r\n\r\n";
    const result = stripChunkSizeLines(text);
    assert.equal(result.hasTerminal, true);
    assert.ok(result.stripped.includes("hello"));
    assert.equal(rawBytesHaveTerminal(Buffer.from(text, "latin1")), true);
    assert.equal(rawBytesHaveTerminal(Buffer.from("10\r\n\r\n", "latin1")), false);
  });
});
