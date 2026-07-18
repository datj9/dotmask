import crypto from "node:crypto";

// ── AI API domains to intercept ───────────────────────────────────────────────
export const AI_DOMAINS = new Set([
  "api.anthropic.com",
  "api.openai.com",
  "openrouter.ai",
  "api.openrouter.ai",
  "generativelanguage.googleapis.com",
  "api.deepseek.com",
  "api.groq.com",
  "api.moonshot.ai",
  "api.together.ai",
  "api.fireworks.ai",
  "api.cerebras.ai",
  "api.x.ai",
  "api.inference.huggingface.co",
  "api.minimax.io",
  "api.minimax.chat",
]);

export function isAiDomain(host: string): boolean {
  const bare = host.replace(/:\d+$/, "");
  return AI_DOMAINS.has(bare);
}

// ── Known token patterns ──────────────────────────────────────────────────────
// All alternatives are listed separately for readability; joined at runtime.
const KNOWN_TOKEN_PARTS = [
  String.raw`eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{20,}`, // JWT
  String.raw`AKIA[A-Z0-9]{16}`,                                                    // AWS key ID
  String.raw`sk_live_[A-Za-z0-9]{24,}`,                                            // Stripe live
  String.raw`sk_test_[A-Za-z0-9]{20,}`,                                            // Stripe test
  String.raw`sk-ant-api\d{2}-[A-Za-z0-9\-_+/]{20,}`,                              // Anthropic
  String.raw`sk-proj-[A-Za-z0-9\-_+/]{20,}`,                                      // OpenAI project
  String.raw`sk-or-v1-[A-Za-z0-9\-_+/]{20,}`,                                     // OpenRouter
  String.raw`sk-proxy-[A-Za-z0-9\-_+/]{20,}`,                                     // generic proxy
  String.raw`sk-[A-Za-z0-9\-_+/]{20,}`,                                           // generic sk-
  String.raw`AIza[A-Za-z0-9\-_]{35,}`,                                             // Google AI
  String.raw`suiprivkey[a-z0-9]{40,}`,                                             // Sui (bech32)
  String.raw`0x[0-9a-fA-F]{64}`,                                                   // EVM private key
  String.raw`ghp_[A-Za-z0-9+/]{30,}`,                                             // GitHub PAT
  String.raw`gho_[A-Za-z0-9+/]{30,}`,                                             // GitHub OAuth
  String.raw`github_pat_[A-Za-z0-9_]{25,}`,                                        // GitHub fine-grained
  String.raw`xoxb-[A-Za-z0-9\-+/]{20,}`,                                          // Slack bot
  String.raw`xoxp-[A-Za-z0-9\-+/]{20,}`,                                          // Slack user
  String.raw`(?:postgres|mysql|mongodb):\/\/\S+:\S+@\S+`,                          // DB URLs
];
const KNOWN_TOKEN_RE = new RegExp(
  `(?<![A-Za-z0-9_/+])(${KNOWN_TOKEN_PARTS.join("|")})(?![A-Za-z0-9_+/])`,
  "g",
);


const SECRET_KEY_RE = /KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|AUTH/i;
const HIGH_ENTROPY_TOKEN_RE = /(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{20,}={0,2})(?![A-Za-z0-9+/_=-])/g;

// ── Fake token generation ─────────────────────────────────────────────────────
const KNOWN_PREFIXES = [
  /^(sk-ant-api\d+-)/,
  /^(sk-proj-)/,
  /^(sk-or-v1-)/,
  /^(sk-proxy-)/,
  /^(sk_live_)/,      // Stripe live (underscore)
  /^(sk_test_)/,      // Stripe test (underscore)
  /^(sk-live-)/,
  /^(sk-test-)/,
  /^(sk-[a-zA-Z0-9]+-)/,
  /^(sk-)/,
  /^(AKIA)/,          // AWS Access Key ID
  /^(AIza)/,
  /^(suiprivkey)/,
  /^(0x)/,
  /^(ghp_)/,
  /^(gho_)/,
  /^(github_pat_)/,
  /^(xoxb-)/,
  /^(xoxp-)/,
  /^(postgres:\/\/[^:]+:)/,
  /^(mysql:\/\/[^:]+:)/,
  /^(mongodb:\/\/[^:]+:)/,
];

function detectCharset(value: string, payload: string): string {
  if (value.startsWith("AKIA")) return "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  if (value.startsWith("sk_live_") || value.startsWith("sk_test_")) {
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  }
  if (value.startsWith("ghp_") || value.startsWith("gho_")) {
    return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  }
  if (value.startsWith("github_pat_")) return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
  if (value.startsWith("suiprivkey")) return "1qpzry9x8gf2tvdw0s3jn54khce6mua7l";

  if (/^[0-9]+$/.test(payload)) return "0123456789";
  if (/^[0-9a-f]+$/.test(payload)) return "0123456789abcdef";
  if (/^[0-9A-F]+$/.test(payload)) return "0123456789ABCDEF";
  if (/^[0-9a-fA-F]+$/.test(payload)) return "0123456789abcdefABCDEF";
  if (/^[A-Z0-9]+$/.test(payload)) return "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  if (/^[a-z0-9]+$/.test(payload)) return "abcdefghijklmnopqrstuvwxyz0123456789";
  if (/^[A-Za-z0-9]+$/.test(payload)) return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  // Check URL-safe charset before standard Base64 so token shape remains valid.
  if (/^[A-Za-z0-9_-]+$/.test(payload)) return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
  // Only use standard Base64 charset when the payload genuinely contains + or /
  if (/^[A-Za-z0-9+/]+=*$/.test(payload)) return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
}

function extractPrefix(value: string): string {
  for (const pat of KNOWN_PREFIXES) {
    const m = value.match(pat);
    if (m) return m[1];
  }
  // Unknown secret formats must not reveal a plaintext prefix.
  return "";
}

// Per-process keyed pseudonyms are deterministic for the lifetime of the proxy,
// but cannot be recomputed by an API provider that knows the source code.
const FAKE_HMAC_KEY = crypto.randomBytes(32);

function keyedChars(value: string, domain: string, length: number, charset: string): string {
  let result = "";
  let counter = 0;
  while (result.length < length) {
    const digest = crypto
      .createHmac("sha256", FAKE_HMAC_KEY)
      .update(domain)
      .update("\0")
      .update(value)
      .update("\0")
      .update(String(counter++))
      .digest();
    for (const byte of digest) {
      result += charset[byte % charset.length];
      if (result.length === length) break;
    }
  }
  return result;
}

export function makeFake(value: string): string {
  if (value.length < 8) return value;

  // JWT special case: preserve the three-part dot-separated structure (header.payload.signature).
  // The fake starts with "eyJ" so it remains recognisable as a JWT.
  if (value.startsWith("eyJ")) {
    const parts = value.split(".");
    if (parts.length === 3) {
      const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
      const fakeParts = parts.map((part, idx) => {
        const chars = keyedChars(value, `jwt:${idx}`, part.length, charset);
        return idx === 0 ? "eyJ" + chars.slice(3) : chars;
      });
      return fakeParts.join(".");
    }
  }

  const prefix = extractPrefix(value);
  const payload = value.slice(prefix.length);
  if (!payload) return value;

  const charset = detectCharset(value, payload);
  const stripped = payload.replace(/=+$/, "");
  const padding = "=".repeat(payload.length - stripped.length);

  const fake = keyedChars(value, "token", stripped.length, charset) + padding;

  return prefix + fake;
}

// ── Shannon entropy ───────────────────────────────────────────────────────────
function shannonEntropy(s: string): number {
  const counts: Record<string, number> = {};
  for (const c of s) counts[c] = (counts[c] ?? 0) + 1;
  const len = s.length;
  return -Object.values(counts).reduce((acc, v) => {
    const p = v / len;
    return acc + p * Math.log2(p);
  }, 0);
}

function isHighEntropySecret(value: string): boolean {
  if (value.length < 20 || value.includes("...")) return false;
  if (/^0x[0-9a-fA-F]{40}$/.test(value)) return false; // public EVM address
  const entropy = shannonEntropy(value);
  if (entropy >= 3.5 && /^[A-Za-z0-9+/\-_=]{20,}$/.test(value)) return true;
  if (/^[0-9a-fA-F]{64,}$/.test(value)) return true;
  if (value.length >= 40 && /^[A-Za-z0-9+/]{40,}={0,2}$/.test(value)) return true;
  return false;
}

// Secret mappings are deliberately request-local. Real values are never
// written to disk, Keychain, logs, or a process-wide cache.
export function loadRealToFakeMap(): Map<string, string> {
  return new Map();
}

function registerMapping(real: string, fake: string, realToFake: Map<string, string>): void {
  if (real !== fake) realToFake.set(real, fake);
}

// ── Core masking (request: real → fake) ──────────────────────────────────────

export function maskText(text: string, realToFake: Map<string, string>): { masked: string; count: number } {
  let masked = text;
  let count = 0;

  // 1. Replace known registered real values (longest first)
  const sorted = [...realToFake.entries()].sort((a, b) => b[0].length - a[0].length);
  for (const [real, fake] of sorted) {
    if (masked.includes(real)) {
      masked = masked.split(real).join(fake);
      count++;
    }
  }

  // 2. Scan for well-known token patterns.
  masked = masked.replace(KNOWN_TOKEN_RE, (token) => {
    if ([...realToFake.values()].includes(token)) return token; // already fake
    const fake = makeFake(token);
    if (fake === token) return token;
    registerMapping(token, fake, realToFake);
    count++;
    return fake;
  });

  // 3. Mask standalone high-entropy values, including encoded tool output.
  const knownFakes = new Set(realToFake.values()); // fakes registered so far
  masked = masked.replace(HIGH_ENTROPY_TOKEN_RE, (token) => {
    if ([...knownFakes].some((fake) => fake.includes(token)) || !isHighEntropySecret(token)) return token;
    const existing = realToFake.get(token);
    const fake = existing ?? makeFake(token);
    if (fake === token) return token;
    registerMapping(token, fake, realToFake);
    knownFakes.add(fake);
    count++;
    return fake;
  });

  // 4. Scan env-var assignment lines, including lower-entropy passwords.
  masked = masked.replace(
    /^([A-Za-z_][A-Za-z0-9_]*)=(.+)$/gm,
    (line, key: string, rawValue: string) => {
      const value = rawValue.trim();
      const quoted =
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"));
      const unquoted = quoted ? value.slice(1, -1) : value;

      const isSecretKey = SECRET_KEY_RE.test(key);
      if ((isSecretKey && unquoted.length >= 8) || isHighEntropySecret(unquoted)) {
        if (realToFake.has(unquoted)) return line;  // already registered as real
        if (knownFakes.has(unquoted)) return line;  // already a fake — don't double-mask
        const fake = makeFake(unquoted);
        if (fake === unquoted) return line;
        registerMapping(unquoted, fake, realToFake);
        knownFakes.add(fake);
        count++;
        if (value.startsWith('"')) return `${key}="${fake}"`;
        if (value.startsWith("'")) return `${key}='${fake}'`;
        return `${key}=${fake}`;
      }
      return line;
    },
  );

  return { masked, count };
}

/**
 * Mask secrets in a parsed Anthropic/OpenAI messages array (request).
 */
export function maskMessages(messages: unknown[], realToFake?: Map<string, string>): number {
  return maskJsonPayload(messages, realToFake);
}

/**
 * Recursively mask every string leaf in an AI JSON request. Secret-looking
 * property names receive stricter treatment so ordinary passwords are covered.
 */
export function maskJsonPayload(body: unknown, realToFake?: Map<string, string>): number {
  const map = realToFake ?? loadRealToFakeMap();
  let total = 0;

  function maskString(value: string, keyHint: string): string {
    const result = maskText(value, map);
    total += result.count;
    if (result.count > 0 || !SECRET_KEY_RE.test(keyHint) || value.length < 8) {
      return result.masked;
    }

    const fake = map.get(value) ?? makeFake(value);
    if (fake === value) return value;
    registerMapping(value, fake, map);
    total++;
    return fake;
  }

  function walk(node: unknown, keyHint = ""): unknown {
    if (typeof node === "string") return maskString(node, keyHint);
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) node[i] = walk(node[i], keyHint);
      return node;
    }
    if (typeof node !== "object" || node === null) return node;

    const record = node as Record<string, unknown>;
    for (const [key, value] of Object.entries(record)) record[key] = walk(value, key);
    return record;
  }

  walk(body);
  return total;
}
