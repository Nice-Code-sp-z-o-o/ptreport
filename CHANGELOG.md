# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
