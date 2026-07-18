# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 2.x | Yes |
| 1.x | No — response unmasking is unsafe |

## Reporting a vulnerability

Please report vulnerabilities privately to the maintainer before public disclosure. Include the affected version, reproduction steps, impact, and any suggested mitigation. Avoid including live credentials in reports.

## Security design

Dotmask 2 is a one-way redaction proxy:

- Only exact allowlisted hostnames are intercepted.
- Upstream TLS certificate validation remains enabled.
- Supported request bodies are scanned before forwarding.
- Malformed, compressed, binary, and unsupported bodies are blocked for intercepted hosts.
- JSON traversal covers every string leaf, with stricter handling for secret-named properties.
- Pseudonyms use a random process-local HMAC key and do not reveal prefixes for unknown formats.
- Real secret mappings are request-local and are not persisted.
- Provider responses are never unmasked. This prevents model-controlled text and tool calls from acting as a secret-resolution oracle.
- The CA private key and CA directory use restrictive filesystem permissions.
- Claude Code trusts the CA through `NODE_EXTRA_CA_CERTS`; no system-wide trust is installed.

## Threat model and limitations

Dotmask is intended to reduce accidental disclosure in AI prompts and tool results. It does not protect against:

- A local agent that already has permission to read files, environment variables, Keychain entries, or process memory.
- Tool calls that send local data directly to another host.
- Secrets in provider authentication headers; those must reach the provider.
- Traffic to non-allowlisted hosts, which is tunneled without inspection.
- Novel encodings, fragments, or formats that evade both known-pattern and entropy detection.
- A compromised local user account, proxy process, Node runtime, OpenSSL binary, or generated CA private key.

Treat dotmask as defense in depth. Keep agent tool approvals enabled, sandbox untrusted repositories, restrict outbound network access, and use short-lived least-privilege credentials.

## Upgrade and cleanup

Installing version 2 removes a legacy dotmask CA from the login Keychain when present. `dotmask uninstall` fails visibly if daemon or trust cleanup fails, removes legacy mapping entries it can identify, and deletes `~/.dotmask` only after the preceding cleanup succeeds.
