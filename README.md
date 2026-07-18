# dotmask

Best-effort, one-way secret redaction for AI API requests on macOS.

`dotmask` runs a local HTTPS proxy for Claude Code. Before a supported request reaches an allowed AI provider, it replaces recognized credentials and high-entropy values with keyed, format-preserving fakes. Provider responses are forwarded unchanged: dotmask never inserts a real secret into assistant text or model-generated tool arguments.

## Install

```bash
npm install -g @ducnmm/dotmask
dotmask install
```

Restart Claude Code after installation. The generated proxy CA is scoped to Claude Code with `NODE_EXTRA_CA_CERTS`; dotmask does not install a system-trusted root.

Version 2 is intentionally incompatible with the old response-unmasking behavior. Tool calls that contain a fake credential must obtain the real credential from a trusted local environment at execution time.

## Commands

- `dotmask install [--port <n>]` — install and start the proxy
- `dotmask allow <host>` — add an intercepted provider hostname
- `dotmask disallow <host>` — remove an intercepted hostname
- `dotmask hosts` — list intercepted hostnames
- `dotmask status` — show proxy status
- `dotmask doctor` — diagnose installation issues
- `dotmask uninstall` — remove the daemon, settings, legacy trust, certificates, mappings, and logs

## Security behavior

For allowlisted hosts, dotmask:

1. Terminates the client's TLS connection locally.
2. Rejects compressed, binary, malformed JSON, and unsupported request bodies instead of forwarding them uninspected.
3. Recursively scans every string in JSON requests, plus supported textual request bodies.
4. Replaces known token formats, secret-named properties, environment assignments, and high-entropy values.
5. Forwards provider responses byte-for-byte without restoring secrets.

Fakes are derived with a random, process-local HMAC key. They are stable during one proxy run but cannot be recomputed offline by the provider. Real-to-fake mappings are request-local and real secrets are not persisted by dotmask.

## Supported providers

The default allowlist includes Anthropic, OpenAI, OpenRouter, Google AI, DeepSeek, Groq, Moonshot, Together, Fireworks, Cerebras, xAI, Hugging Face, and MiniMax endpoints. `~/.dotmask/config.json` controls the exact list.

## Important limitations

Dotmask reduces accidental disclosure; it is not a sandbox, DLP system, or authorization boundary.

- Provider authentication headers are not masked because the provider requires them. The provider receives those credentials, although the model normally does not.
- Traffic to non-allowlisted hosts is passed through without inspection.
- A model with filesystem or shell-tool permission may read or exfiltrate local data outside the AI request path. Use tool approvals, sandboxing, least-privilege credentials, and network controls.
- Pattern and entropy detection can have false negatives and false positives. Unsupported request formats are blocked for intercepted hosts.
- Fakes deliberately cannot be converted back into real credentials by model output. Generated commands should reference local environment variables or another trusted credential mechanism.

## Debugging

```bash
tail -f ~/.dotmask/proxy.err.log
DOTMASK_DEBUG=1 node dist/proxy/server.js --port 18787
```

Debug logs contain counts and connection metadata, not request or response bodies.

## Requirements

- macOS
- Node.js 18+
- `openssl`

## License

MIT
