# AI agent integrations

ptreport can be the **system of record for AI pentest agents**: autonomous red-team agents (Decepticon),
verifying scanners (pentest-ai / `ptai`), reverse-engineering agents driving Ghidra or IDA, or your own scripts.

The rule: **nothing an agent sends reaches a report without a human accepting it.** Agents create
*proposals*. Proposals wait in the report's **AI queue** (report page → **AI queue**), where you accept them as
new findings, merge them into existing ones, or reject them. Every proposal is validated with the same rules as
manual input when it arrives *and again* when you accept it, and accepting is all-or-nothing.

- [How results get in](#how-results-get-in)
- [The AI queue](#the-ai-queue)
- [ptreport proposal JSON v1](#ptreport-proposal-json-v1)
- [MCP server: `ptreport mcp`](#mcp-server-ptreport-mcp)
- [Integration tokens and the API](#integration-tokens-and-the-api)
- [Security notes](#security-notes)

## How results get in

| Way | For | Auth |
|---|---|---|
| `POST /api/v1/reports/<id>/proposals` | any agent, CI job or script | integration token with scope `propose` (or the main API token) |
| `ptreport mcp` (MCP server, stdio) | agent clients: Claude Code, Codex, Cursor … | none: it runs as your user, over stdio |
| Report → **Import AI results** / `ptreport import-ai` | SARIF 2.1.0, ptai proof capsules, proposal JSON files | the web UI / your shell |

## The AI queue

Pending proposals are grouped by kind. Each shows the tool, version, run id, model and verdict, a summary
(title, severity, CVSS, CWE, targets, the start of the description, number of HTTP / code / file evidence items)
and **Show everything** with the full text, requests, responses and code.

A **duplicate hint** appears when a finding proposal looks like a finding already in the report: the same CWE on
an overlapping target (same host) or in the same source file, or a title at least 80 % similar
(`difflib.SequenceMatcher` ratio ≥ 0.8).

| Action | Finding proposal | Evidence / code / file | Retest result | Target |
|---|---|---|---|---|
| **Accept** | new finding, status *Open* | added to the finding it names (or the one you pick) | fills *Retest result*, date and notes | new target (an existing one with the same address is reused) |
| **Merge** | evidence, code, files and targets go to the finding you pick; its text stays | – | – | – |
| **Reject** | nothing is written | | | |

Tick several proposals and use **Accept selected** / **Reject selected** for bulk decisions (bulk accept never
merges).

On accept:

- the verdict becomes the finding's confidence: `verified` → *Certain*, `candidate` → *Unknown* (an unconfirmed
  lead; the app has no "candidate" confidence), no verdict → the proposal's own `confidence`, if any;
- the finding's **origin** is filled, e.g. `ptai 1.6.2 · run 7f3a · verified · model claude-x`. The report page
  and the finding page show a small **AI** badge with the origin as tooltip. The origin is not printed in
  HTML / Markdown / PDF exports; the JSON backup carries it, and *Duplicate* / *Create retest report* keep it;
- the finding's history gets `Added from <tool> (<run>) – AI proposal accepted` (merge: `Merged AI proposal
  from …`; retest: `Retest: Not fixed – from … – AI proposal accepted`);
- HTTP evidence is stored with the source `ai`; files get their SHA-256 computed by ptreport.

A retest proposal never changes the finding's status: that stays your decision.

## ptreport proposal JSON v1

The format any agent can produce. Send it to the API, put it in a file for **Import AI results**, or let the MCP
tools build it for you.

### Envelope

A request body or file is one of:

- a single proposal object;
- a list of proposal objects (at most 200);
- an envelope with a default `source` for all proposals:

```json
{
  "format": "ptreport-proposals",
  "version": 1,
  "source": {"tool": "ptai", "version": "1.6.2", "run_id": "7f3a", "model": "claude-x"},
  "proposals": [ … ]
}
```

### Proposal

```json
{
  "kind": "finding",
  "verdict": "verified",
  "source": {"tool": "ptai", "version": "1.6.2", "run_id": "7f3a", "model": "claude-x"},
  "finding_id": 12,
  "data": { … }
}
```

| Field | Type | Notes |
|---|---|---|
| `kind` | string, required | `finding`, `evidence` (HTTP), `code`, `file`, `retest`, `target` |
| `verdict` | string | `verified` (the tool's own oracle confirmed it), `candidate` (unconfirmed), or empty |
| `source` | object | `tool` (≤ 100), `version` (≤ 50), `run_id` (≤ 100), `model` (≤ 100); single-line text. Overrides the envelope's `source` field by field |
| `finding_id` | integer | required for `evidence`, `code`, `file`, `retest`: the id of a finding **in the same report** (see `GET /reports/<id>/findings` or the MCP tool `get_report`) |
| `data` | object | the kind's fields (below). The fields may also be given next to `kind` instead of inside `data` |

Limits: 200 proposals per request, 40 MB per stored proposal, 50 targets / evidence items / code snippets and
10 files per proposal, plus every limit of the field it lands in (titles 300 characters, texts 200 000, HTTP
messages 5 MB, files 25 MB each and 100 MB per finding).

### `finding`

```json
{
  "kind": "finding",
  "verdict": "verified",
  "data": {
    "title": "Reflected XSS in search",
    "severity": "medium",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "cwe": "CWE-79",
    "description": "The q parameter is reflected without HTML encoding.",
    "impact": "Script execution in the victim's session.",
    "technical_details": "Oracle: unescaped_reflection, replayed 3/3.",
    "poc": "```\ncurl 'https://shop.example/search?q=<script>alert(1)</script>'\n```",
    "remediation": "Encode output for the HTML context.",
    "refs": ["https://owasp.org/www-community/attacks/xss/"],
    "targets": ["https://shop.example", {"name": "router.bin", "kind": "firmware", "address": "fw/router-2.1.bin"}],
    "evidence": [{"title": "Reflection", "request": "GET /search?q=%3Cscript%3E HTTP/1.1\r\nHost: shop.example\r\n\r\n",
                  "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>"}],
    "code_evidence": [{"title": "Sink", "location": "web/search.py:42 render_results", "language": "python",
                       "code": "return f'<p>{q}</p>'"}],
    "files": [{"filename": "search.har", "description": "Browser capture", "data_base64": "eyJsb2ciOnt9fQ=="}]
  }
}
```

| Field | Notes |
|---|---|
| `title` | required, ≤ 300 |
| `severity` | `critical`, `high`, `medium`, `low`, `info` (`informational` is accepted). Missing → the CVSS rating is used as a suggestion; missing without CVSS → error |
| `cvss_vector` | CVSS 4.0 / 3.1 / 3.0 / 2.0 vector, validated and scored by ptreport; `cvss_version` is optional (detected) |
| `cwe` | `CWE-79`, `79` or `79` as a number |
| `description`, `impact`, `technical_details`, `poc`, `remediation` | text (fenced code blocks, Markdown tables) |
| `refs` | text, one reference per line, or a list of strings |
| `confidence` | `certain`, `probable`, `unknown`; only used when `verdict` is empty |
| `targets` | addresses (a URL becomes a web target named after its host, anything else a host) or objects `{name, kind, address, description}`; `kind` is one of `web, api, host, network, mobile, cloud, wireless, binary, firmware, other`. A target with the same address that is already in the report is reused |
| `evidence` | HTTP request/response pairs `{title, request, response}`; `request` is required |
| `code_evidence` | `{title, location, language, code, note}` – see `code` |
| `files` | `{filename, description, data_base64[, sha256]}`; when `sha256` is given it must match |

Status, finding ID, retest fields and the CVSS score are never taken from a proposal.

### `evidence` (HTTP)

```json
{"kind": "evidence", "finding_id": 12, "data": {"title": "Still reflected", "request": "GET / HTTP/1.1\r\n…", "response": "HTTP/1.1 200 OK\r\n…"}}
```

### `code`

```json
{"kind": "code", "finding_id": 12, "verdict": "candidate",
 "data": {"title": "Hard-coded key check", "location": "firmware/bin/auth:check_pw @ 0x401a2c",
          "language": "pseudo", "code": "if (strcmp(input, \"s3cr3t\") == 0) { grant(); }",
          "note": "Ghidra decompilation, function renamed by the agent."}}
```

`language`: `c`, `cpp`, `asm`, `pseudo`, `java`, `python`, `text`. `location` is free text (file, function,
address; ≤ 300), `code` ≤ 200 000 characters, `note` ≤ 20 000.

### `file`

```json
{"kind": "file", "finding_id": 12, "data": {"filename": "router-2.1.bin", "description": "Analysed sample", "data_base64": "…"}}
```

Same rules as uploads: 25 MB per file, 100 MB and 50 files per finding, the name is cleaned, the MIME type comes
from the extension, the SHA-256 is computed by ptreport (and printed in the report). Attach the samples you
analysed as files, so the client can verify exactly what was reversed.

### `retest`

```json
{"kind": "retest", "finding_id": 12, "verdict": "verified",
 "data": {"result": "not_fixed", "date": "2026-11-20", "notes": "The payload still executes.",
          "evidence": [{"request": "…", "response": "…"}], "code_evidence": []}}
```

`result` (required): `fixed`, `partially_fixed`, `not_fixed`, `not_tested`. `date` defaults to the day you accept
it.

### `target`

```json
{"kind": "target", "data": {"name": "Router firmware 2.1", "kind": "firmware", "address": "fw/router-2.1.bin"}}
```

## MCP server: `ptreport mcp`

`ptreport mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server over **stdio**
(newline-delimited JSON-RPC 2.0). It is built into ptreport, needs no extra package, and works on the same
database as the running web app (WAL mode, one transaction per write), so you can keep the browser open on the
AI queue while the agent works.

```bash
ptreport mcp                       # all reports, read + propose tools
ptreport mcp --report 3            # pin every call to report 3 (report_id becomes optional)
ptreport mcp --read-only           # hide the propose_* tools
ptreport mcp --data-dir ~/cases/acme/ptreport-data
```

Only protocol messages are written to stdout; logs go to stderr. Supported methods: `initialize` (protocol
versions 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05; the client's version when supported, otherwise the
newest), `notifications/initialized`, `ping`, `tools/list`, `tools/call`. Errors follow JSON-RPC (`-32700` parse
error, `-32600` invalid request, `-32601` unknown method, `-32602` invalid params / unknown tool); a tool call
that fails validation returns `isError: true` with the field errors, so the model can correct itself.

| Tool | Does |
|---|---|
| `list_reports` | reports with client, dates, finding counts, pending proposals |
| `get_report` | summary, targets and findings (id, display id, title, severity, status, CWE, CVSS, retest result, origin) |
| `get_scope` | the engagement scope ([below](#scope-for-agents)); `format: "markdown"` for a short brief |
| `search_cwe` | the bundled MITRE CWE catalogue |
| `list_templates` | the finding template library (EN/PL) |
| `list_proposals` | the report's AI queue and the decisions taken |
| `propose_finding` | a new finding with targets, HTTP evidence and code evidence |
| `propose_http_evidence` | a request/response for an existing finding |
| `propose_code_evidence` | a code snippet (decompiled function, disassembly, source) for an existing finding |
| `propose_file` | a file (base64, ≤ 25 MB) for an existing finding |
| `propose_retest_result` | an explicit retest result for a finding |

Every `propose_*` tool takes an optional `verdict` and `source` (`tool`, `version`, `run_id`, `model`); without a
source the MCP client's name is recorded (e.g. `claude-code (MCP)`). **Write tools only create proposals.**

### Register it

ptreport must be on the client's `PATH` (`install.sh` links it into `~/.local/bin`); GUI clients may need the
absolute path (`which ptreport`).

**Claude Code**

```bash
claude mcp add ptreport -- ptreport mcp
claude mcp add ptreport-acme -- ptreport mcp --report 3      # one engagement only
```

**Codex CLI** – `codex mcp add ptreport -- ptreport mcp`, or in `~/.codex/config.toml`:

```toml
[mcp_servers.ptreport]
command = "ptreport"
args = ["mcp"]
```

**Cursor** – `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one project):

```json
{"mcpServers": {"ptreport": {"command": "ptreport", "args": ["mcp", "--report", "3"]}}}
```

Any other MCP client: command `ptreport`, arguments `mcp …`, transport stdio.

### Recommended setup: one agent client, several MCP servers

Register the offensive tools **and** ptreport in the same agent client. The agent then drives the tools and pushes
what it found into ptreport's AI queue in the same session; you review in the browser.

```bash
claude mcp add ptreport   -- ptreport mcp --report 3
claude mcp add decepticon -- decepticon mcp serve        # autonomous red team (PurpleAILAB)
ptai setup --mcp                                          # pentest-ai: registers its own MCP server
claude mcp add ghidra     -- <your Ghidra / IDA MCP bridge command>   # reverse engineering
```

A prompt that works well: *"Read the scope with ptreport get_scope (report 3). Test only those targets. For every
issue you can verify, call ptreport propose_finding with the request/response that proves it, verdict and
source; attach code locations with propose_code_evidence."*

## Integration tokens and the API

**Settings → Integrations** creates tokens for agents and tools. Give each a name and its scopes:

| Scope | Allows |
|---|---|
| `read` | `GET /reports`, `/reports/<id>`, `/reports/<id>/targets`, `/reports/<id>/findings`, `/findings/<id>`, `/reports/<id>/scope`, `/reports/<id>/proposals`, `/cwe`, `/templates` |
| `propose` | `POST /reports/<id>/proposals` only |

A token is shown **once**, when it is created; ptreport stores only its SHA-256 and compares in constant time.
**Revoke** stops it immediately. The main API token (Settings → API access, used by the Burp extension) keeps full
access. Proposal creation is rate limited per token (a burst of 400 proposals, then 2 per second).

```bash
TOKEN=ptr_...   # Settings -> Integrations
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind":"finding","verdict":"verified","source":{"tool":"my-agent","run_id":"42"},
       "data":{"title":"Directory listing on /backup/","severity":"low","targets":["https://shop.example"]}}' \
  http://127.0.0.1:5055/api/v1/reports/3/proposals

curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:5055/api/v1/reports/3/proposals?status=pending"
```

`201` returns the stored proposals (file contents replaced by size and SHA-256) and the `review_url` of the queue.
`422` returns `{"error": "validation_failed", "errors": {"[0].data.cvss_vector": "…"}}` and stores nothing.
`403` means the token lacks the scope, `429` that it sends too fast.

## Security notes

- **Proposals only.** No agent path writes findings, evidence or retest results. The MCP server's write tools and
  the `propose` scope create proposals; a person accepts them in the browser (CSRF protected).
- **Untrusted input.** Proposal payloads, SARIF files and capsules are treated as hostile: sizes and nesting
  are limited, types and lengths checked, CVSS vectors scored by ptreport, CWE ids normalised, base64 decoded
  strictly with the evidence-file limits. Everything is validated again before it is applied, and shown as
  text (never rendered as HTML).
- **Scoped tokens.** Give an agent `propose` (and `read` if it needs the scope); never the main API token. Tokens
  are stored hashed and can be revoked.
- **Loopback.** The web app and API listen on 127.0.0.1 by default. The MCP server talks only over stdio (no
  port at all) and runs with your user's access to the database.
