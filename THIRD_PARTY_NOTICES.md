# Third-party software and data

ptreport itself is released under the [Apache License 2.0](LICENSE). It uses or ships the following third-party
components, each under its own license.

## Python dependencies (installed from PyPI, not vendored)

Pinned with hashes in [`requirements.lock`](requirements.lock).

| Package | License |
|---|---|
| Flask, Werkzeug, Jinja2, MarkupSafe, itsdangerous, click | BSD-3-Clause (Pallets) |
| blinker | MIT |
| cvss (Red Hat) | LGPL-3.0-or-later, used unmodified as a separate library |

## Shipped with ptreport

| Component | Where | License |
|---|---|---|
| MITRE CWE List 5.0 (names, descriptions, mitigations) | `src/ptreport/data/cwe.json.gz` | CWE Terms of Use, see [`CWE-LICENSE.txt`](src/ptreport/data/CWE-LICENSE.txt). CWE is a trademark of The MITRE Corporation. |
| Hanken Grotesk, JetBrains Mono (woff2) | `src/ptreport/static/fonts/`, `design/system/fonts/` | SIL Open Font License 1.1, see `OFL.txt` next to the fonts |

## Downloaded at install or build time (not in this repository)

| Component | When | License |
|---|---|---|
| [Tectonic](https://tectonic-typesetting.github.io) 0.17.0, LaTeX engine for PDF export | `install.sh`, SHA-256 checked | MIT |
| TeX packages fetched by Tectonic on first use | first PDF | their own free licenses (LPPL and others) |
| [Burp Montoya API](https://github.com/PortSwigger/burp-extensions-montoya-api) 2026.7 | `burp-extension/build.sh`, SHA-256 checked; compile-only, **not** bundled in `ptreport-burp.jar` | PortSwigger |

Burp Suite is a trademark of PortSwigger Ltd. ptreport is not affiliated with or endorsed by PortSwigger,
MITRE, Tenable (Nessus), OWASP (ZAP), Greenbone (OpenVAS) or the Nmap project; their names are used only to
describe the file formats ptreport can import.
