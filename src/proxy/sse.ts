export interface ChunkedParseResult {
  payloads: Buffer[];
  terminal: boolean;
}

export const TERMINAL_CHUNK = Buffer.from("0\r\n\r\n", "ascii");

export function encodeChunkedPayload(payload: Buffer | string): Buffer {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8");
  return Buffer.concat([
    Buffer.from(`${body.length.toString(16)}\r\n`, "ascii"),
    body,
    Buffer.from("\r\n", "ascii"),
  ]);
}

export class IncrementalChunkedBodyParser {
  private buffer: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  private ended = false;

  push(chunk: Buffer): ChunkedParseResult {
    if (this.ended) return { payloads: [], terminal: true };

    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    const payloads: Buffer[] = [];

    while (this.buffer.length > 0) {
      const lineEnd = this.buffer.indexOf("\r\n");
      if (lineEnd === -1) break;

      const sizeLine = this.buffer.toString("ascii", 0, lineEnd).trim();
      const sizeHex = sizeLine.split(";", 1)[0];
      if (!/^[0-9a-fA-F]+$/.test(sizeHex)) throw new Error(`invalid chunk size line: ${sizeLine}`);

      const len = Number.parseInt(sizeHex, 16);
      const payloadStart = lineEnd + 2;
      if (len === 0) {
        let trailerOffset = payloadStart;
        while (true) {
          const trailerEnd = this.buffer.indexOf("\r\n", trailerOffset);
          if (trailerEnd === -1) return { payloads, terminal: false };
          if (trailerEnd === trailerOffset) {
            this.buffer = this.buffer.subarray(trailerEnd + 2);
            this.ended = true;
            return { payloads, terminal: true };
          }
          trailerOffset = trailerEnd + 2;
        }
      }

      const payloadEnd = payloadStart + len;
      if (this.buffer.length < payloadEnd + 2) break;
      if (this.buffer[payloadEnd] !== 0x0d || this.buffer[payloadEnd + 1] !== 0x0a) {
        throw new Error("invalid chunk payload terminator");
      }

      payloads.push(Buffer.from(this.buffer.subarray(payloadStart, payloadEnd)));
      this.buffer = this.buffer.subarray(payloadEnd + 2);
    }

    return { payloads, terminal: false };
  }
}

export function decodeChunked(buffer: Buffer): Buffer {
  const chunks: Buffer[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    const nextCrLf = buffer.indexOf("\r\n", offset);
    if (nextCrLf === -1) break;
    const sizeLine = buffer.toString("ascii", offset, nextCrLf).trim();
    const sizeHex = sizeLine.split(";", 1)[0];
    if (!/^[0-9a-fA-F]+$/.test(sizeHex)) throw new Error("invalid chunk size");
    const len = Number.parseInt(sizeHex, 16);
    if (len === 0) break;
    const payloadStart = nextCrLf + 2;
    const payloadEnd = payloadStart + len;
    if (buffer.length < payloadEnd + 2) throw new Error("truncated chunked body");
    if (buffer[payloadEnd] !== 0x0d || buffer[payloadEnd + 1] !== 0x0a) {
      throw new Error("invalid chunk payload terminator");
    }
    chunks.push(buffer.subarray(payloadStart, payloadEnd));
    offset = payloadEnd + 2;
  }
  return Buffer.concat(chunks);
}

export function getCompleteChunkedMessageLength(buffer: Buffer): number | null {
  let offset = 0;
  while (offset < buffer.length) {
    const lineEnd = buffer.indexOf("\r\n", offset);
    if (lineEnd === -1) return null;

    const sizeLine = buffer.toString("ascii", offset, lineEnd).trim();
    const sizeHex = sizeLine.split(";", 1)[0];
    if (!/^[0-9a-fA-F]+$/.test(sizeHex)) throw new Error("invalid chunk size");
    const len = Number.parseInt(sizeHex, 16);
    offset = lineEnd + 2;

    if (len === 0) {
      while (true) {
        const trailerStart = offset;
        const trailerEnd = buffer.indexOf("\r\n", offset);
        if (trailerEnd === -1) return null;
        offset = trailerEnd + 2;
        if (trailerEnd === trailerStart) return offset;
      }
    }

    const chunkEnd = offset + len;
    if (buffer.length < chunkEnd + 2) return null;
    if (buffer[chunkEnd] !== 0x0d || buffer[chunkEnd + 1] !== 0x0a) {
      throw new Error("invalid chunk payload terminator");
    }
    offset = chunkEnd + 2;
  }
  return null;
}

export function stripChunkSizeLines(text: string): { stripped: string; hasTerminal: boolean } {
  let hasTerminal = false;
  const stripped = text
    .replace(/\r\n/g, "\n")
    .replace(/^([0-9a-fA-F]+)(?:;[^\n]*)?\n/gm, (_, hex) => {
      if (Number.parseInt(hex, 16) === 0) hasTerminal = true;
      return "";
    });
  return { stripped, hasTerminal };
}

export function rawBytesHaveTerminal(buf: Buffer): boolean {
  for (let i = 0; i <= buf.length - 5; i++) {
    const startsAtLineBoundary = i === 0 || (buf[i - 2] === 0x0d && buf[i - 1] === 0x0a);
    if (!startsAtLineBoundary) continue;
    if (buf[i] === 0x30 && buf[i + 1] === 0x0d && buf[i + 2] === 0x0a &&
        buf[i + 3] === 0x0d && buf[i + 4] === 0x0a) return true;
  }
  return false;
}
