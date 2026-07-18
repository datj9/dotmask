# Architecture

## Overview

Dotmask is a local, one-way HTTPS redaction proxy for allowlisted AI API hosts. Its invariant is:

> Provider-controlled responses must never cause a real secret to be materialized.

## Request flow

```text
Claude Code
    │ HTTPS_PROXY + NODE_EXTRA_CA_CERTS
    ▼
127.0.0.1 dotmask proxy
    │
    ├─ non-allowlisted host → ordinary CONNECT passthrough
    │
    └─ allowlisted host → local TLS termination
         │
         ├─ parse complete HTTP/1.1 request
         ├─ reject compressed/binary/unsupported bodies
         ├─ recursively redact supported request content
         ├─ validate upstream TLS normally
         └─ forward provider response byte-for-byte
```

## Components

### CLI and installation

`src/cli.ts` dispatches installation, status, host-management, doctor, and uninstall commands. `src/commands/install.ts` manages Claude Code's `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS` settings.

The CA is not added as a system-trusted root. The CA private key is stored at `~/.dotmask/ca/ca.key.pem` with mode `0600`, and the CA directory uses mode `0700`.

### Proxy server

`src/proxy/server.ts` accepts connections only on `127.0.0.1`. Exact allowlisted hostnames are MITM-intercepted; other hosts are tunneled without inspection. Upstream connections use Node TLS validation with the target hostname as SNI.

Responses are intentionally opaque to dotmask and are never rewritten.

### HTTP sanitization

`src/proxy/http.ts` parses request framing and implements fail-closed body handling:

- JSON and `+json` bodies must parse as an object or array.
- Text, form, GraphQL, and XML bodies are scanned as UTF-8 text.
- Compressed, binary, and unsupported bodies are rejected.
- Content length is recalculated after redaction.

### Masker

`src/proxy/masker.ts` recursively visits every string leaf in JSON. Detection combines:

- Known credential formats such as common AI, cloud, GitHub, Slack, JWT, database, and private-key tokens.
- Secret-looking property and environment-variable names.
- High-entropy token candidates, including encoded tool output.

Fakes preserve length and known structural prefixes. Unknown formats preserve no plaintext prefix. A random process-local HMAC key makes output stable during one daemon run without making it predictable to the provider.

Mappings exist only in the `Map` passed through one request traversal. Dotmask 2 performs no Keychain writes and stores no real-secret mapping on disk.

## Legacy migration

Version 1 persisted fake-to-real mappings and installed the CA into the login Keychain. Version 2 no longer uses either mechanism. Installation removes legacy CA trust; uninstall additionally deletes identifiable legacy Keychain mappings and `~/.dotmask` after successful daemon, trust, and settings cleanup.
