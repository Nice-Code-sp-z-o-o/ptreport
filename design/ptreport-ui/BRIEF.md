# Brief: ptreport-ui

Date: 2026-11-25.

## What the product is

ptreport is a local-first pentest report generator (Flask + Jinja, SQLite, runs on 127.0.0.1). No accounts, no cloud,
no brand yet. The current look (`src/ptreport/static/app.css`, `report.css`) was built as a functional first pass
on the same day and carries no brand decisions: it is evidence, not authority (Replace).

## To whom

Penetration testers, working alone or in small teams, usually on Kali/Linux next to Burp Suite and a terminal.
They document findings during and right after an engagement, often late, often fast. The exported report is read by
the client: management reads the summary, developers read the technical part.

## What blocks the job today

Writing a finding means moving between many fields (title, CVSS, CWE, targets, description, PoC, HTTP evidence) and
the report only shows its real shape in the export. The UI should make the report's state readable at a glance
(how many findings, how severe, what is incomplete) and make entering a finding fast.

## Surfaces

| Surface | What it has to do | Mode |
|---|---|---|
| Report list (`/`) | find the engagement, see its size and severity at a glance | Operate |
| Report view (`/reports/<id>`) | severity summary, findings table with numbering and order, targets, export | Operate |
| Finding editor (`/findings/<id>/edit`) | fast entry: CVSS calculator (4.0/3.1/3.0/2.0), CWE, targets, text fields, HTTP evidence | Operate |
| Exported report (HTML -> PDF via print) | client-facing document: cover, TOC, summary, findings with PoC and evidence | Read |

## What exists

No mark, no colours, no typeface. Demo data: `design/ptreport-ui/data/` (captured from the running app).
Severity scale: Critical, High, Medium, Low, Informational. Report headings EN/PL.

## What must not be touched

Product function and data model, field set, CVSS logic (server-side), security constraints: no inline scripts or
styles in app pages (CSP `script-src 'self'; style-src 'self'`), all user content escaped, the exported HTML has
no scripts and works offline (fonts must be self-hosted/embedded or system).

## References

- 169 GitHub Advisory Database: severity label, id and CWE in one dense row; filters left of the list. How security
  people already scan findings.
- 168 FIRST CVSS 4.0 calculator: metric groups as rows of segmented buttons with live score. The interaction
  pentesters know; we keep the grouping, not the look.
- 134 Linear: a working tool with density that stays calm; keyboard-first shell.
