# Contributing to ptreport

Thanks for helping! Bug reports, ideas and pull requests are welcome.

## Before you start

- For a bigger change, open an issue first so we can agree on the approach.
- Security problems: see [SECURITY.md](SECURITY.md), not the public tracker.
- By contributing you agree that your contribution is released under the [MIT License](LICENSE).

## Development setup

```bash
git clone https://github.com/Nice-Code-sp-z-o-o/ptreport.git
cd ptreport
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]' ruff
.venv/bin/ptreport --data-dir ./data      # http://127.0.0.1:5055
```

PDF export needs a LaTeX engine: run `./install.sh` once (it downloads Tectonic), or install `xelatex`, or set
`PTREPORT_TECTONIC=/path/to/tectonic`. Without one, the LaTeX tests are skipped.

## Checks (CI runs the same)

```bash
.venv/bin/python -m pytest          # all tests
.venv/bin/ruff check src tests      # lint
cd burp-extension && ./build.sh     # Burp extension (Java 17+)
```

## Guidelines

- **Tests are required** for new features and bug fixes: the happy path, validation errors, and the
  security-relevant edge cases (CSRF, escaping, limits).
- **No new dependencies** unless there is no reasonable way around it; explain why in the PR. No CDN assets:
  everything is served locally.
- **Validate on the server.** HTML attributes are only for UX.
- **Database changes** go in a new migration appended to `MIGRATIONS` in `src/ptreport/db.py`; never edit an
  existing one.
- **UI** reuses the existing macros, components and CSS tokens; icons are stroke SVG symbols in
  `templates/_icons.html`. No inline scripts or styles (CSP).
- Keep exports in sync: HTML, Markdown, LaTeX/PDF and the JSON backup (plus import) for anything stored per report.
- After changing the Burp extension, run `burp-extension/build.sh` and commit the updated
  `src/ptreport/data/ptreport-burp.jar`.
- Commit messages: short imperative subject, then what and why.

## Pull requests

Fill in the PR template, keep the change focused, and add screenshots for UI changes.
