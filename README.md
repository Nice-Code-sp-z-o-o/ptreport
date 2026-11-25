# ptreport

A pentest report generator that runs on your own machine. Everything stays local:
one SQLite file, no accounts, no cloud.

- **Reports**: client, assessors, testing period, executive summary, scope, methodology
- **Targets**: web apps, APIs, hosts, network ranges, mobile apps…
- **Findings**: title, automatic numbering (`ACME-001`, `ACME-002`, …, with your own prefix),
  clickable **CVSS 4.0 / 3.1 / 3.0 / 2.0** calculator, **CWE** (autocomplete), description,
  impact, technical details, **PoC**, remediation, references, affected targets, status
- **HTTP evidence**: raw request/response pairs for each finding (the Burp extension will send these)
- **Screenshots**: PNG/JPEG images per finding, numbered as figures across the report (type is checked
  from the file's bytes; SVG is rejected). Exports embed them, so the HTML/PDF/Markdown stay self-contained
- **Confidence** per finding (certain / probable / unknown)
- **Report metadata**: prepared by (company) and contact, report version, report date, version history table
- **PDF from LaTeX**: the default PDF template is LaTeX (typeset by Tectonic, installed with ptreport);
  you can upload your own template in Settings or download the LaTeX sources of a report
- **Export**: PDF, standalone HTML, Markdown, LaTeX sources (.zip), JSON (backup or sharing), with report
  headings in English or Polish
- **Changelogs**: report version history (version, date, author, description, editable) and a history per
  finding (status changes are recorded automatically, retest notes by hand); each can be hidden in exports
- **Finding templates**: a library of reusable write-ups in English and Polish (12 common vulnerabilities
  ship as a starter set); start a finding from a template, save any finding as a template, import/export JSON
- **Scanner import**: Burp Suite XML, Nessus, Nmap, OWASP ZAP and OpenVAS/Greenbone reports become targets and
  findings (with evidence); you review the list and tick what to add
- **Retests**: create a retest report from an existing one, record the retest result, date and notes per finding,
  and get a "Retest summary" section in the report
- **Tables** in text fields (Markdown pipe tables), rendered in HTML and in the PDF
- **Notes** per report: working notes (raw results, questions, to-dos) with search and pinning; never in the report
- **Burp Suite extension**: right-click a request or response and send it to a new or existing finding, choosing
  the title, CWE, severity and target in a dialog
- **JSON API** with bearer-token auth (used by the Burp extension)

## Install (one command)

```bash
./install.sh
```

Requires Python 3.10+ and `curl`. On Kali, Debian or Ubuntu you may first need `sudo apt install python3-venv`.
The installer also downloads **Tectonic** (a self-contained LaTeX engine, pinned version with a SHA-256 check)
into `~/.local/share/ptreport/tectonic` and typesets a sample report once, so LaTeX packages are cached and
PDF export then works offline. If Tectonic is not available, ptreport uses `xelatex`/`lualatex` from the system.
The script creates an isolated virtualenv in `~/.local/share/ptreport/venv`, installs pinned,
**hash-verified** dependencies from `requirements.lock`, and links `ptreport` into `~/.local/bin`.

Uninstall with `./install.sh --uninstall`. Your data is kept.

## Run (one command)

```bash
ptreport
```

This opens <http://127.0.0.1:5055/> in your browser. Options:

| Option | Description |
|---|---|
| `--port 8080` | Use a different port |
| `--data-dir PATH` | Use a different database/secret location (default `~/.local/share/ptreport/data`; you can also set `PTREPORT_DATA_DIR`) |
| `--no-browser` | Don't open the browser |
| `--show-api-token` | Print the API token for the Burp extension and exit |
| `--host 0.0.0.0 --allow-host my-laptop.lan` | Expose on the LAN. **Not recommended:** there is no login screen |

## Writing findings

- **Finding IDs**: the format is set in **Settings → Finding IDs** as a template: `{prefix}` (the report's
  prefix), `{n}` or `{n:4}` (the number, zero padded), `{year}` (year of testing), e.g. `{prefix}-{n:4}` gives
  `LT-0002`. You can also set the first number and the default prefix for new reports. A report can override the
  format in its details, and a single finding can have its own ID (e.g. when copying an existing report).
- **Numbering**: a new finding gets the next number. Reorder with ↑/↓, or click
  **Renumber by severity** (Critical first, then by CVSS score). Deleting a finding closes the gap.
- **CVSS**: pick a version and click the metrics, or paste a vector; the version is detected
  automatically. The server computes the score and its CVSS rating (None/Low/Medium/High/Critical).
- **Severity is yours**: it is always set by the tester and never derived from CVSS, so it can reflect context
  (chained issues, compensating controls). Reports show both: your severity and, separately, the CVSS score with
  its rating. An empty severity is pre-filled from the CVSS rating as a suggestion only.
- **Text fields** are plain text with fenced code blocks (```` ``` ````) and `` `inline code` ``.
  Payloads like `<script>` are always shown as text, never executed.
- **Tables**: write a Markdown pipe table in any text field:

  ```
  | Port | Service |
  |------|:-------:|
  | 443  | https   |
  ```

  `:---:` centres a column, `---:` aligns it right, `\|` is a literal pipe inside a cell.
- **Templates** (top menu): search by title, tag or CWE and filter by language. On a new finding pick
  **Start from a template**; it fills the form and nothing is saved until you create the finding. **Save as
  template** on a finding copies its saved write-up (no targets, evidence or screenshots) into the library, in the
  report's language. The starter set is installed once; templates you delete stay deleted.
- **Scanner import** (report → **Import scan**): upload the file (format detected automatically, informational
  issues left out unless you tick them), review the findings and targets found, tick what to keep. Targets that
  are already in the report (same address) are reused; imported findings start as "Open" with a history entry
  naming the scanner. XML is parsed with entity declarations rejected (no XXE, no entity expansion).
- **Retest**: on a report, **Create retest report** copies targets, findings (with evidence and screenshots),
  structure and CWE texts into a new report linked to the original, with a **Retest summary** section first. Set
  *Retest result* (fixed / partially fixed / not fixed / not tested), date and notes on each finding; a change is
  logged in its history. **Duplicate report** makes an independent copy.
- **PDF**: **Preview PDF** opens the PDF typeset from the LaTeX template; Export → PDF downloads it.

## Report structure, CWE groups, wording

- **Report → Report structure** sets the order, titles, level (section/subsection), numbering and page breaks of
  the sections, and lets you add text sections (e.g. "Future directions", an appendix), charts (findings by
  severity, per target, CVSS versus severity) and tables of findings. Built-in sections can be switched off.
- Text fields support `## Heading`, `### Subheading`, `- list items`, `**bold**`, `` `code` ``, fenced code
  blocks and links; headings become numbered subsections in the PDF.
- **Group findings by CWE** (report details) lays out the findings section per CWE: a description of the
  weakness, its findings, then one mitigation for the group (findings without a CWE form the last group).
- **CWE library** (Settings): the full MITRE CWE catalogue (names, descriptions, potential mitigations) is built
  in, works offline and is refreshed with `scripts/update_cwe.py`. Write your own description and mitigation per
  CWE; reports grouped by CWE use, in this order: the report's own text, your library entry, MITRE's text (can be
  switched off). CWE data is (c) MITRE, terms in `src/ptreport/data/CWE-LICENSE.txt`.
- **Report language** is chosen when a report is created (English or Polish headings); Settings sets the default.
- **Settings → Report wording** renames severities, statuses and headings per language (e.g. "New" instead of
  "Open").
- **Preview PDF** shows the real PDF typeset from the LaTeX template.

## PDF and LaTeX templates

**Export → PDF (LaTeX)** typesets the report with the active template; **Export → LaTeX sources** gives a
zip with `report.tex` and its assets to tweak and compile yourself (`tectonic report.tex`).

The default template ("Corporate Band") has a cover with a band in your brand colour and your logo, a
confidentiality label on the cover and in every footer, a severity bar chart, zebra tables, a card per finding
and framed HTTP request/response blocks. **Settings → Branding** sets the colour and the logo; the
confidentiality label (e.g. `TLP:AMBER`) is a field of each report. The template starts with an
`EDIT HERE` block (colour, fonts, logo, label, severity colours), so a downloaded copy is easy to rebrand.

Templates are Jinja with LaTeX-friendly delimiters: `\VAR{report.title}` prints a value and
`\BLOCK{for f in findings} ... \BLOCK{endfor}` controls the flow; lines starting with `%#` are template
comments. Everything printed with `\VAR` is **escaped for LaTeX automatically**, so report content can
never inject LaTeX commands, also in custom templates. Raw HTTP messages and code blocks are written to
files and loaded with `\VerbatimInput`, so they are never parsed as TeX. Templates run in Jinja's sandbox,
and LaTeX always runs without shell escape. In **Settings → PDF template** you can download the default,
upload your own (it is test-rendered before saving) and switch back to the default.

## Burp Suite extension

Right-click any request or response in Burp (Proxy history, Repeater, Target, Logger, Intruder results ...) and
choose **Send to ptreport**. A dialog asks for:

- the **report** (the last one used is preselected),
- **New finding** (title, **CWE** with search over the whole MITRE catalogue, severity, target) or **Add to an
  existing finding**,
- the evidence title and whether to include the response.

Selecting several requests adds each one as a separate HTTP evidence item. A target matching the request's host is
preselected, or created from it. Afterwards you can open the finding in ptreport.

**Build and load** (JDK 17+; no Gradle needed):

```bash
./burp-extension/build.sh          # -> burp-extension/dist/ptreport-burp.jar
```

In Burp: *Extensions → Installed → Add → Java* and pick `ptreport-burp.jar`. Then open the **ptreport** tab in
Burp, paste the API token (`ptreport --show-api-token`, or Settings → API in ptreport) and click *Test
connection*. The build downloads the Montoya API (PortSwigger's official extension API, compile-time only; Burp
provides it at runtime) from Maven Central and checks its SHA-256. The token is kept in Burp's user settings, not in
project files.

## API (for the Burp extension)

Base URL: `http://127.0.0.1:5055/api/v1`, header `Authorization: Bearer <token>`.
The token is shown under **Settings** and can be regenerated there.

| Method | Path | Purpose |
|---|---|---|
| GET | `/ping` | Health / version |
| GET | `/reports` | List reports |
| GET | `/reports/{id}` | Report details |
| GET/POST | `/reports/{id}/targets` | List / create targets |
| GET/POST | `/reports/{id}/findings` | List / create findings (optional inline `evidence` list) |
| GET | `/findings/{id}` | Finding with evidence |
| POST | `/findings/{id}/evidence` | Attach a raw HTTP request/response |
| POST | `/findings/{id}/attachments` | Attach a screenshot: `{"caption": "...", "data_base64": "..."}` |
| GET | `/templates?language=en&q=xss` | Finding template library |
| GET | `/cwe?q=xss` | MITRE CWE catalogue (`{"id": "CWE-79", "name": ...}`) |
| GET/POST | `/reports/{id}/notes` | List / add working notes |

```bash
TOKEN=$(ptreport --show-api-token)
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"IDOR in /api/orders/{id}","cvss_version":"3.1",
       "cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N","cwe":"639",
       "evidence":[{"title":"Order of another user","request":"GET /api/orders/2 HTTP/1.1\r\nHost: shop\r\n\r\n"}]}' \
  http://127.0.0.1:5055/api/v1/reports/1/findings
```

Validation errors return `422 {"error":"validation_failed","errors":{field: message}}`.

## Security model

The tool stores sensitive client data, so it protects itself even though it only runs on localhost:

- Listens on `127.0.0.1` only by default. The database folder is `0700`, and the secrets are `0600`.
- A **Host header allow-list** blocks DNS-rebinding attacks from malicious pages open in your browser.
- Every browser form has **CSRF tokens**. Session cookies are `SameSite=Strict` and `HttpOnly`.
- A strict **CSP** (`script-src 'self'`, no inline scripts) plus `X-Frame-Options: DENY`, `nosniff`, and `no-referrer`.
- **Validation** happens server-side on every write path (forms, API, import). Client-side checks only help with UX.
- All SQL uses bound parameters. All user content is HTML-escaped. Reference links are only made for `http(s)`.
- The API uses a random bearer token, compared in constant time. The API sends no CORS headers.

## Development

```bash
uv venv && uv pip install -e ".[dev]"     # or: python -m venv .venv && pip install -e ".[dev]"
.venv/bin/pytest                           # tests
uvx ruff check src tests                   # lint
uvx pip-audit -r requirements.lock --require-hashes   # dependency audit
.venv/bin/ptreport --data-dir ./data       # run against a throwaway DB
```

To regenerate the lock file after changing dependencies:
`uv pip compile pyproject.toml --generate-hashes --python-version 3.10 -o requirements.lock`

### Dependencies

Two runtime dependencies are pinned in `requirements.lock`:

- **Flask**: web framework. It brings Werkzeug, Jinja2 and MarkupSafe.
- **cvss** (Red Hat Product Security): the official FIRST scoring algorithms for CVSS 2.0, 3.x and 4.0.
  CVSS 4.0 scores come from a macro-vector lookup table, which is error-prone to re-implement.
  The CVSS specifications are stable, so infrequent releases are expected. The repository is maintained
  and not archived.

### Layout

```
src/ptreport/
  cli.py            entry point (`ptreport`)
  app.py            Flask app factory, error handling
  db.py             SQLite connection + schema migrations (PRAGMA user_version)
  repo.py           all SQL (parameterised)
  validation.py     server-side validation for forms / API / import
  cvss_service.py   CVSS scoring + calculator metric definitions
  cwe.py            curated CWE list for autocomplete
  security.py       Host allow-list, CSRF, API token, security headers
  views.py          browser UI
  api.py            JSON API v1
  export.py         HTML / Markdown / JSON export, JSON import
  importers.py      scanner parsers (Burp, Nessus, Nmap, ZAP, OpenVAS), hardened XML loading
  latex.py          LaTeX rendering + PDF compilation (Tectonic)
  data/             MITRE CWE catalogue, starter finding templates
  rendering.py      safe rich-text rendering, report labels (EN/PL)
  templates/ static/
tests/              pytest suite
```
