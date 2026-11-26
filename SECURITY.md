# Security policy

ptreport stores penetration test findings, which are often confidential. We take vulnerabilities in it
seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report it privately through GitHub: **Security → Report a vulnerability** on this repository
(GitHub private vulnerability reporting). Include:

- the version or commit,
- what an attacker can do and under which conditions,
- steps to reproduce or a proof of concept.

We aim to acknowledge a report within 5 working days and to agree on a fix and disclosure date with you.
We are happy to credit you in the release notes.

## Supported versions

Only the latest release (and `main`) receives security fixes.

## Security model in short

- The web app listens on **127.0.0.1** by default and rejects foreign `Host` headers (DNS rebinding).
  Binding to another interface needs an explicit `--host` plus `--allow-host`.
- Every form is CSRF-protected; the JSON API (`/api/v1`) needs a bearer token.
- Strict Content-Security-Policy, no inline scripts; user content is escaped, Markdown is rendered by our
  own restricted renderer.
- Uploaded files are never rendered: downloads are `attachment` + `nosniff` + sandbox CSP, active types
  are served as `application/octet-stream`. Scanner XML is parsed with entities disabled (XXE / billion laughs).
- LaTeX runs without shell escape; only the bundled or a test-rendered custom template is used.
- The optional AI assistant only talks to an Ollama server on loopback (SSRF guard, no redirects, no proxies).
- Data lives in a local SQLite database in your data directory; ptreport makes no outbound connections
  except the ones you start (Tectonic package downloads, Ollama on localhost).

In scope: anything that lets a remote web page, an imported file (scanner XML, JSON backup, screenshot,
evidence file, LaTeX template) or a crafted HTTP request read or change data, run code, or reach the network.

Out of scope: attacks that need local access to your user account or data directory, and running ptreport
deliberately exposed to an untrusted network.
