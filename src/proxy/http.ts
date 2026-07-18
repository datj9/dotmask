import { decodeChunked, getCompleteChunkedMessageLength } from "./sse.js";
import { maskJsonPayload, maskText } from "./masker.js";

const MAX_HEADER_BYTES = 64 * 1024;
const MAX_BODY_BYTES = 16 * 1024 * 1024;
const MAX_CHUNKED_WIRE_BYTES = MAX_BODY_BYTES + 1024 * 1024;

export interface ParsedHttpRequest {
  requestLine: string;
  headers: Record<string, string>;
  body: Buffer;
  bytesConsumed: number;
}

export function sanitizeRequestBody(
  rawBody: Buffer,
  contentType: string,
  contentEncoding: string,
): { body: Buffer; count: number } {
  if (rawBody.length === 0) return { body: rawBody, count: 0 };
  if (contentEncoding && contentEncoding.toLowerCase() !== "identity") {
    throw new Error(`unsupported request content-encoding: ${contentEncoding}`);
  }

  const realToFake = new Map<string, string>();
  if (/^application\/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)/i.test(contentType)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawBody.toString("utf8"));
    } catch {
      throw new Error("invalid JSON request body");
    }
    if (typeof parsed !== "object" || parsed === null) {
      throw new Error("AI JSON request body must be an object or array");
    }

    const count = maskJsonPayload(parsed, realToFake);
    return { body: Buffer.from(JSON.stringify(parsed), "utf8"), count };
  }

  const isTextual = contentType === "" ||
    /^text\//i.test(contentType) ||
    /^(?:application\/(?:x-www-form-urlencoded|graphql|xml)|application\/[a-z0-9.+-]+\+xml)(?:\s*;|$)/i.test(contentType);
  if (!isTextual || rawBody.includes(0)) {
    throw new Error(`unsupported request content-type: ${contentType || "(missing)"}`);
  }

  const result = maskText(rawBody.toString("utf8"), realToFake);
  return { body: Buffer.from(result.masked, "utf8"), count: result.count };
}

export function parseCompleteHttpRequest(buffer: Buffer): ParsedHttpRequest | null {
  const headerEnd = buffer.indexOf("\r\n\r\n");
  if (headerEnd === -1) {
    if (buffer.length > MAX_HEADER_BYTES) throw new Error("request headers exceed 64 KiB");
    return null;
  }
  if (headerEnd > MAX_HEADER_BYTES) throw new Error("request headers exceed 64 KiB");

  const headerText = buffer.toString("latin1", 0, headerEnd);
  const lines = headerText.split("\r\n");
  const requestLine = lines[0] ?? "";
  const headers: Record<string, string> = {};

  for (const line of lines.slice(1)) {
    const idx = line.indexOf(":");
    if (idx <= 0) throw new Error("malformed request header");
    const name = line.slice(0, idx).trim().toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) throw new Error("invalid request header name");
    if (Object.prototype.hasOwnProperty.call(headers, name)) {
      throw new Error(`duplicate request header: ${name}`);
    }
    headers[name] = line.slice(idx + 1).trimStart();
  }

  const bodyStart = headerEnd + 4;
  const rawBody = buffer.subarray(bodyStart);
  if (headers["transfer-encoding"] && headers["content-length"]) {
    throw new Error("ambiguous request framing");
  }
  if (headers["transfer-encoding"]) {
    if (headers["transfer-encoding"].toLowerCase() !== "chunked") {
      throw new Error("unsupported transfer-encoding");
    }
    if (rawBody.length > MAX_CHUNKED_WIRE_BYTES) throw new Error("request body exceeds 16 MiB");
    const chunkedLength = getCompleteChunkedMessageLength(rawBody);
    if (chunkedLength === null) return null;

    const chunkedBody = rawBody.subarray(0, chunkedLength);
    const decoded = decodeChunked(chunkedBody);
    if (decoded.length > MAX_BODY_BYTES) throw new Error("request body exceeds 16 MiB");
    return {
      requestLine,
      headers,
      body: decoded,
      bytesConsumed: bodyStart + chunkedLength,
    };
  }

  const contentLength = headers["content-length"] ?? "0";
  if (!/^\d+$/.test(contentLength)) throw new Error("invalid content-length");
  const bodyExpected = Number.parseInt(contentLength, 10);
  if (!Number.isSafeInteger(bodyExpected) || bodyExpected > MAX_BODY_BYTES) {
    throw new Error("request body exceeds 16 MiB");
  }
  if (rawBody.length < bodyExpected) return null;

  return {
    requestLine,
    headers,
    body: rawBody.subarray(0, bodyExpected),
    bytesConsumed: bodyStart + bodyExpected,
  };
}
