"""Finding ID formatting.

A template mixes literal text with placeholders:
  {prefix}  the report's finding prefix (e.g. ACME)
  {n}       the finding's number; {n:4} pads it with zeros to 4 digits
  {year}    the year the testing started (or the current year)
Examples: "{prefix}-{n:3}" -> ACME-001, "{prefix}-{n:4}" -> LT-0002, "{year}/{prefix}/{n:2}" -> 2026/ACME/01.
"""

from __future__ import annotations

import re
from datetime import date

DEFAULT_TEMPLATE = "{prefix}-{n:3}"
DEFAULT_START = 1
DEFAULT_PREFIX = "VULN"
MAX_TEMPLATE_LEN = 40
MAX_START = 9999

_TOKEN = re.compile(r"\{(prefix|year|n(?::([1-6]))?)\}")
_LITERAL = re.compile(r"^[A-Za-z0-9._:#/ -]*$")


def template_error(template: str) -> str | None:
    """Return an error message, or None when the template is valid."""
    if not template:
        return "ID format is required."
    if len(template) > MAX_TEMPLATE_LEN:
        return f"ID format must be at most {MAX_TEMPLATE_LEN} characters."
    if len(re.findall(r"\{n(?::[1-6])?\}", template)) != 1:
        return "ID format must contain the number exactly once: {n}, or {n:3} for zero padding (1-6 digits)."
    literal = _TOKEN.sub("", template)
    if "{" in literal or "}" in literal:
        return "Unknown placeholder. Use {prefix}, {n}, {n:3} or {year}."
    if not _LITERAL.match(literal):
        return "ID format may contain letters, digits, spaces and . _ : # / - besides the placeholders."
    return None


def render(template: str, prefix: str, number: int, year: int | None = None) -> str:
    def repl(m: re.Match) -> str:
        name, width = m.group(1), m.group(2)
        if name == "prefix":
            return prefix
        if name == "year":
            return str(year or date.today().year)
        return str(number).zfill(int(width)) if width else str(number)

    return _TOKEN.sub(repl, template)


def report_year(report: dict) -> int | None:
    start = report.get("start_date") or ""
    return int(start[:4]) if len(start) >= 4 and start[:4].isdigit() else None
