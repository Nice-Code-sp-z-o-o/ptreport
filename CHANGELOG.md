# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- AI intake queue: agents create proposals (findings, HTTP evidence, code evidence, files, retest results,
  targets) that wait per report until you accept, merge or reject them; duplicate hints, bulk actions,
  re-validation on accept. Accepted findings keep their origin (tool, run, verdict, model) as an "AI" badge.
- Integration tokens with `read` / `propose` scopes (Settings → Integrations), stored hashed, revocable;
  `GET/POST /api/v1/reports/<id>/proposals` with per-token rate limiting.
- `ptreport mcp`: a Model Context Protocol server over stdio (no new dependency) with read tools and
  proposal-only write tools; `--report` and `--read-only`.
- Import of SARIF 2.1.0, pentest-ai proof capsules and ptreport proposal JSON v1 into the AI queue (web and
  `ptreport import-ai`); in retest reports matching results become "not fixed" retest proposals.
- Code evidence on findings (HTML / Markdown / PDF, JSON backup, API) and the target types *binary* and
  *firmware* for reverse engineering.
- Engagement scope for agents: `ptreport scope`, `GET /api/v1/reports/<id>/scope`, MCP `get_scope`.
- `docs/integrations.md`: proposal schema, MCP setup, Decepticon / pentest-ai / RE recipes.

## [0.1.0]

First public version.

### Added
- Reports, targets and findings with automatic numbering, CVSS 4.0 / 3.1 / 3.0 / 2.0 calculator, full MITRE CWE
  5.0 catalogue, rich text with tables, references, history and nine finding statuses.
- HTTP evidence, screenshots with an in-browser editor (crop, arrows, boxes, irreversible pixelation, original
  kept), and evidence files of any type with a server-side SHA-256.
- PDF export via LaTeX (Tectonic) with a customisable template, plus HTML, Markdown, LaTeX source and JSON backup
  / restore.
- Report structure editor, CWE grouping, wording overrides per language (English and Polish), branding.
- Finding template library (EN/PL), retest reports, report duplication, working notes per report.
- Scanner import: Burp Suite, Nessus, Nmap, OWASP ZAP, OpenVAS / Greenbone.
- Burp Suite extension ("Send to ptreport") and a bearer-token JSON API.
- Command-line interface (`report list/create/show`, `import-scan`, `export`, `import-json`).
- Optional local AI writing assistant via Ollama (off by default, loopback only).
- One-command install (`install.sh`).
