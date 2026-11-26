# AI import fixtures

- `ptai-capsule.json` – the real `ptai-demo-capsule.json` from https://github.com/0xSteph/pentest-ai (main
  branch, fetched 2026-11-26). Kept byte-for-byte (it is already small), so its `integrity_sha256` still matches.
- `ptai.sarif` – hand-written in the shape of pentest-ai's SARIF exporter (`engine/sarif.py` plus the
  verified-only properties of `engine/exporters/contract.py`: `verdict`, `oracle_kind`, `replay`). Not real tool
  output.
- `code-scan.sarif` – hand-written in the style of Semgrep / CodeQL output (rule tags with CWE ids,
  `security-severity`, file locations with snippets, a duplicate, a suppressed and a passing result).
- `proposals.json` – ptreport proposal JSON v1 envelope (see `docs/integrations.md`).
All hosts are `.example` / loopback.
