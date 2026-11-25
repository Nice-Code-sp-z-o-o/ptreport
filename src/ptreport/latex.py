"""PDF reports typeset with LaTeX.

The template is Jinja with LaTeX-friendly delimiters:
    \\VAR{expr}            output (escaped for LaTeX automatically)
    \\BLOCK{for x in xs}   statements
    \\#{comment}           comments
Every value printed with \\VAR is escaped unless it is ``TexSafe`` - only this module's filters produce
that (rich text, verbatim inputs, images). User content therefore can never inject LaTeX commands, also
in custom templates. Raw text that must stay verbatim (HTTP messages, code blocks) is written to files
and loaded with fvextra's \\VerbatimInput, so it is never parsed as TeX at all.

Compilation uses Tectonic (installed with ptreport) or, if absent, xelatex/lualatex from the system,
always without shell escape.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
from collections import OrderedDict
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from jinja2 import StrictUndefined, TemplateError
from markupsafe import Markup
from jinja2.sandbox import SandboxedEnvironment

from ptreport.cvss_service import vector_strip
from ptreport.cwe import cwe_name, cwe_url
from ptreport.rendering import (
    CONFIDENCE_LABELS,
    CVSS_RATING_LABELS,
    SEVERITY_LABELS,
    STATUS_LABELS,
    TARGET_KIND_LABELS,
    cvss_rating_key,
    cvss_rating_label,
    inline_tokens,
    labels_for,
    parse_blocks,
    text_blocks,
)

DEFAULT_TEMPLATE_PATH = Path(__file__).parent / "latex" / "report.tex"
COMPILE_TIMEOUT = 300  # the first Tectonic run downloads LaTeX packages
MAX_TEMPLATE_BYTES = 512 * 1024

_URL = re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!&'()*+,;=%-]+$")


_MACRO_BEFORE_VAR = re.compile(r"\\(?!VAR\b|BLOCK\b)([A-Za-z]+)(?=\\VAR\{)")


class TexSafe(Markup):
    """LaTeX source that is already safe to emit as-is (macro output is Markup too)."""


class LatexError(RuntimeError):
    def __init__(self, message: str, log: str = ""):
        super().__init__(message)
        self.log = log


_TEX_ESCAPES = {
    "\\": r"\textbackslash{}", "{": r"\{", "}": r"\}", "$": r"\$", "&": r"\&", "#": r"\#", "%": r"\%",
    "_": r"\_", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}", '"': r"\textquotedbl{}",
    "<": r"\textless{}", ">": r"\textgreater{}", "|": r"\textbar{}",
}
_TEX_RE = re.compile("|".join(re.escape(c) for c in _TEX_ESCAPES))
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def escape_tex(value: object) -> str:
    text = _CONTROL.sub("", str(value))
    return _TEX_RE.sub(lambda m: _TEX_ESCAPES[m.group(0)], text)


def _finalize(value):
    """Every printed value: macro output and filter results (Markup) pass through, the rest is escaped.

    The environment runs with autoescape on, so Jinja wraps what this returns; returning Markup keeps
    Jinja's own (HTML) escaping out of the way."""
    if value is None:
        return Markup("")
    if isinstance(value, Markup):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return Markup(str(value))  # noqa: S704 - a number, no markup
    return Markup(escape_tex(value))  # noqa: S704 - escaped for LaTeX on this line


@dataclass
class Build:
    """Collects the files (verbatim blocks, images) a rendered report needs next to report.tex."""

    files: dict[str, bytes] = field(default_factory=dict)

    def add(self, stem: str, ext: str, data: bytes) -> str:
        name = f"assets/{stem}-{len(self.files) + 1}.{ext}"
        self.files[name] = data
        return name


_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"'`]+")


def _href(value: str) -> str:
    """Clickable, line-breakable link for a URL that passed ``_URL``; anything else is plain text."""
    trail = ""
    while value and value[-1] in ".,;:)":  # sentence punctuation after a URL is not part of it
        trail = value[-1] + trail
        value = value[:-1]
    if not _URL.match(value):
        return escape_tex(value + trail)
    target = value.replace("%", r"\%").replace("#", r"\#")
    return rf"\href{{{target}}}{{\ptUrl{{\nolinkurl{{{target}}}}}}}" + escape_tex(trail)


def _inline_tex(text: str) -> str:
    parts = []
    for kind, value in inline_tokens(text):
        if kind == "code":
            parts.append(rf"\texttt{{{escape_tex(value)}}}")
        elif kind == "bold":
            parts.append(rf"\textbf{{{escape_tex(value)}}}")
        elif kind == "url":
            parts.append(_href(value))
        else:
            parts.append(escape_tex(value))
    return "".join(parts)


def _table_tex(data: dict) -> str:
    """A Markdown table as a page-breaking longtable with equal columns and a repeated header row."""
    n = max(1, len(data["header"]))
    align = {"left": r"\raggedright", "center": r"\centering", "right": r"\raggedleft"}
    cols = "".join(
        rf">{{{align[a]}\arraybackslash}}p{{\dimexpr\linewidth/{n}-2\tabcolsep\relax}}" for a in data["align"]
    )
    head = " & ".join(rf"\ptTableHead{{{_inline_tex(c)}}}" for c in data["header"]) + r" \\"
    rows = "\n".join(" & ".join(r"\small " + _inline_tex(c) for c in row) + r" \\" for row in data["rows"])
    return (
        rf"\ptTableBegin\begin{{longtable}}{{@{{}}{cols}@{{}}}}" + "\n" + head + "\n\\endhead\n"
        + rows + "\n\\end{longtable}\\ptTableEnd"
    )


def _paragraphs(body: str, numbered: bool = True) -> str:
    out = []
    for kind, data in text_blocks(body):
        if kind == "heading":
            level, title = data
            command = "subsection" if level == 2 else "subsubsection"
            text = _inline_tex(title)
            if numbered:
                out.append(rf"\{command}{{{text}}}")
            else:
                out.append(rf"\{command}*{{{text}}}\addcontentsline{{toc}}{{{command}}}{{{text}}}")
        elif kind == "list":
            out.append("\\begin{itemize}\n" + "\n".join(rf"\item {_inline_tex(i)}" for i in data) + "\n\\end{itemize}")
        elif kind == "table":
            out.append(_table_tex(data))
        else:
            out.append("\\newline\n".join(_inline_tex(line) for line in data))
    return "\n\n".join(out)


def make_env(build: Build) -> SandboxedEnvironment:
    env = SandboxedEnvironment(
        block_start_string=r"\BLOCK{", block_end_string="}",
        variable_start_string=r"\VAR{", variable_end_string="}",
        comment_start_string=r"\#{", comment_end_string="}",
        line_comment_prefix="%#",
        trim_blocks=True, lstrip_blocks=True, autoescape=True,
        undefined=StrictUndefined, finalize=_finalize,
    )

    def verbatim_file(text: str, label: str = "code") -> TexSafe:
        """Write raw text to a file next to report.tex; returns its path for \\VerbatimInput."""
        return TexSafe(build.add(label, "txt", (text or "").encode("utf-8")))

    def verbatim(text: str, label: str = "code") -> TexSafe:
        return TexSafe(rf"\ptVerbatim{{{verbatim_file(text, label)}}}")

    def richtext(text: str, numbered: bool = True) -> TexSafe:
        parts = []
        for kind, _lang, body in parse_blocks(text or ""):
            parts.append(verbatim(body) if kind == "code" else _paragraphs(body, bool(numbered)))
        return TexSafe("\n\n".join(p for p in parts if p))

    def url(value: str, text: str | None = None) -> TexSafe:
        value = (value or "").strip()
        if text is None:
            return TexSafe(_href(value))
        if not _URL.match(value):
            return TexSafe(escape_tex(text))
        target = value.replace("%", r"\%").replace("#", r"\#")
        return TexSafe(rf"\href{{{target}}}{{\ptUrl{{{escape_tex(text)}}}}}")

    def reference_list(text: str) -> TexSafe:
        items = [line.strip() for line in (text or "").split("\n") if line.strip()]
        if not items:
            return TexSafe("")
        body = "\n".join(rf"\item {url(i) if _URL.match(i) else escape_tex(i)}" for i in items)
        return TexSafe("\\begin{itemize}\n" + body + "\n\\end{itemize}")

    def image(attachment: dict) -> TexSafe:
        ext = {"image/png": "png", "image/jpeg": "jpg"}.get(attachment["mime"])
        if ext is None or "data" not in attachment:
            return TexSafe(r"\ptMissingImage{}")
        name = build.add("figure", ext, attachment["data"])
        return TexSafe(rf"\ptImage{{{name}}}")

    def asset(obj: dict | None, stem: str = "asset") -> TexSafe:
        """Write an image ({mime, data}) next to report.tex and return its path ('' when unusable)."""
        ext = {"image/png": "png", "image/jpeg": "jpg"}.get((obj or {}).get("mime", ""))
        if not obj or ext is None or not obj.get("data"):
            return TexSafe("")
        return TexSafe(build.add(stem, ext, obj["data"]))

    env.filters.update(
        asset=asset,
        tex=lambda v: TexSafe(escape_tex(v)),
        richtext=richtext,
        verbatim=verbatim,
        verbatim_file=verbatim_file,
        url=url,
        reference_list=reference_list,
        image=image,
        cwe_name=cwe_name,
        cwe_url=cwe_url,
        url_cwe=lambda c: url(cwe_url(c), c),
        cvss_rating_key=cvss_rating_key,
        cvss_rating_label=cvss_rating_label,
        vector_strip=vector_strip,
        score=lambda v: "" if v is None else f"{float(v):.1f}",
        rating_label=lambda r, lang="en": CVSS_RATING_LABELS.get(lang, CVSS_RATING_LABELS["en"]).get(r, r),
    )
    env.globals.update(
        SEVERITY_LABELS=SEVERITY_LABELS, STATUS_LABELS=STATUS_LABELS,
        TARGET_KIND_LABELS=TARGET_KIND_LABELS, CONFIDENCE_LABELS=CONFIDENCE_LABELS,
    )
    return env


def default_template() -> str:
    return DEFAULT_TEMPLATE_PATH.read_text(encoding="utf-8")


def render(ctx: dict, template_source: str | None = None) -> tuple[str, dict[str, bytes]]:
    """Render the LaTeX source. Returns (report.tex text, extra files)."""
    build = Build()
    env = make_env(build)
    try:
        # "\\small\\VAR{x}" would glue the macro to the printed text ("\\smallFixed"): end the macro name first.
        source_text = _MACRO_BEFORE_VAR.sub(r"\\\1{}", template_source or default_template())
        template = env.from_string(source_text)
        source = template.render(**ctx)
    except TemplateError as exc:
        raise LatexError(f"Template error: {exc}") from None
    return source, build.files


def template_problem(template_source: str, sample_ctx: dict) -> str | None:
    """Check that a custom template renders against sample data. Returns an error message or None."""
    if len(template_source.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        return "Template is too large (max 512 KB)."
    if "\\documentclass" not in template_source:
        return "Template must be a complete LaTeX document (\\documentclass ... \\end{document})."
    try:
        render(sample_ctx, template_source)
    except LatexError as exc:
        return str(exc)
    return None


def sample_context() -> dict:
    """A small but complete report used to validate custom templates and to warm the LaTeX cache."""

    finding = {
        "id": 1, "position": 1, "display_id": "PT-001", "external_id": "", "title": "Stored XSS in comments",
        "severity": "high", "status": "fixed", "confidence": "certain", "cvss_version": "3.1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", "cvss_score": 5.4, "cwe": "CWE-79",
        "description": "Comment body is rendered without encoding: <script>alert(1)</script> & 100% {}_^~#$",
        "impact": "Session riding as the victim, see https://owasp.org/www-community/attacks/xss/.",
        "technical_details": "Affected: `POST /api/comments`", "poc": "Payload:\n```\n<img src=x onerror=alert(1)>\n```",
        "remediation": "Encode output.", "refs": "https://owasp.org/www-community/attacks/xss/\nOWASP ASVS V5",
        "targets": [{"id": 1, "name": "Customer portal", "kind": "web", "address": "https://portal.example"}],
        "evidence": [{"title": "Proof", "request": "GET / HTTP/1.1\nHost: portal.example\n\n",
                      "response": "HTTP/1.1 200 OK\n\n<script>alert(1)</script>", "source": "manual"}],
        "attachments": [],
        "history": [{"date": "2026-01-02", "author": "Jan Kowalski", "kind": "status", "status_from": "open",
                     "status_to": "fixed", "description": "", "text": "Status: Open → Fixed"}],
        "history_has_author": True,
        "retest_result": "fixed", "retest_date": "2026-02-01", "retest_notes": "The payload is now encoded.",
    }
    report = {
        "title": "Sample report", "client_name": "ACME", "assessor": "Jan Kowalski", "start_date": "2026-01-01",
        "end_date": "2026-01-02", "language": "en", "finding_prefix": "PT", "executive_summary": "Summary.",
        "scope": "Scope.", "methodology": "OWASP WSTG.", "vendor_name": "ACME Security",
        "vendor_contact": "security@example.com", "report_version": "1.0", "report_date": "2026-01-03",
        "show_version_history": 1, "show_finding_history": 1, "classification": "CONFIDENTIAL",
    }
    version = {"version": "1.0", "date": "2026-01-03", "author": "Jan Kowalski", "description": "Final"}
    counts = {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}
    labels = labels_for("en")
    sections = [{"kind": k, "title": t, "level": 1, "numbered": 1, "new_page": 0, "enabled": 1, "body": ""}
                for k, t in (("executive_summary", "Executive summary"), ("scope", "Scope"),
                             ("methodology", "Methodology"), ("charts", "Results summary"),
                             ("summary", "Summary of findings"), ("retest_summary", "Retest summary"),
                             ("findings", "Findings"))]
    sections.append({"kind": "text", "title": "Appendix", "level": 1, "numbered": 0, "new_page": 1, "enabled": 1,
                     "body": "## Notes\n\n- **one**\n- two"})
    matrix = {s: {r: 0 for r in ("none", "low", "medium", "high", "critical", "")} for s in counts}
    matrix["high"]["medium"] = 1
    groups = [{"cwe": "CWE-79", "title": "CWE-79: Cross-site Scripting", "description": "XSS.",
               "mitigation": "Encode output.", "findings": [finding]}]
    return {
        "sections": sections, "groups": groups, "matrix": matrix, "fingerprint": "0" * 64,
        "per_target": [{"name": "Customer portal", "counts": {**counts}, "total": 1}],
        "sev_labels": labels["sev"], "status_labels": labels["status"], "conf_labels": labels["conf"],
        "report": report, "cvss_header": "CVSS 3.1", "brand": {"color": "1D3557", "logo": None},
        "versions": [version], "all_versions": [version], "versions_have_author": True,
        "show_finding_history": True, "targets": finding["targets"], "findings": [finding], "counts": counts,
        "severities": ("critical", "high", "medium", "low", "info"), "L": labels["L"], "lang": "en",
        "generated_at": "2026-01-03 12:00 UTC",
        "ratings": ("none", "low", "medium", "high", "critical"),
        "original_report": {"id": 0, "title": "Sample report", "report_date": "2026-01-03"},
        "retest_labels": labels["retest"],
        "retest_counts": {k: (1 if k == "fixed" else 0) for k in labels["retest"]},
    }


# ------------------------------------------------------------------ engines --

def _default_tectonic() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(Path.home(), ".local", "share")
    return Path(base) / "ptreport" / "tectonic" / "tectonic"


def find_engine() -> tuple[str, str] | None:
    """(kind, path) of the LaTeX engine to use: Tectonic first, then xelatex, then lualatex."""
    explicit = os.environ.get("PTREPORT_TECTONIC")
    candidates = [explicit] if explicit else []
    # install.sh puts Tectonic next to the app's virtualenv: <APP_HOME>/venv and <APP_HOME>/tectonic
    beside_venv = Path(sys.prefix).parent / "tectonic" / "tectonic"
    candidates += [str(beside_venv), str(_default_tectonic()), shutil.which("tectonic") or ""]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return "tectonic", path
    for name in ("xelatex", "lualatex"):
        path = shutil.which(name)
        if path:
            return name, path
    return None


_PDF_CACHE: OrderedDict[str, bytes] = OrderedDict()
_PDF_CACHE_SIZE = 8
_PDF_CACHE_LOCK = threading.Lock()


def _cache_key(source: str, files: dict[str, bytes], engine: tuple[str, str]) -> str:
    digest = hashlib.sha256()
    digest.update("\0".join(engine).encode())
    digest.update(source.encode("utf-8"))
    for name in sorted(files):
        digest.update(b"\0" + name.encode() + b"\0" + hashlib.sha256(files[name]).digest())
    return digest.hexdigest()


def compile_pdf(source: str, files: dict[str, bytes], timeout: int = COMPILE_TIMEOUT,
                volatile: str = "") -> bytes:
    """Typeset the report. Identical input (an unchanged report) is served from a small in-memory cache,
    so opening the preview again is instant. ``volatile`` (the "generated at" time) is left out of the key."""
    engine = find_engine()
    if engine is not None:
        key = _cache_key(source.replace(volatile, "") if volatile else source, files, engine)
        with _PDF_CACHE_LOCK:
            if key in _PDF_CACHE:
                _PDF_CACHE.move_to_end(key)
                return _PDF_CACHE[key]
        pdf = _compile_pdf(source, files, timeout, engine)
        with _PDF_CACHE_LOCK:
            _PDF_CACHE[key] = pdf
            while len(_PDF_CACHE) > _PDF_CACHE_SIZE:
                _PDF_CACHE.popitem(last=False)
        return pdf
    return _compile_pdf(source, files, timeout, engine)


def _compile_pdf(source: str, files: dict[str, bytes], timeout: int, engine: tuple[str, str] | None) -> bytes:
    if engine is None:
        raise LatexError(
            "No LaTeX engine found. Re-run ./install.sh (it installs Tectonic) or install xelatex."
        )
    kind, path = engine
    with tempfile.TemporaryDirectory(prefix="ptreport-tex-") as tmp:
        workdir = Path(tmp)
        (workdir / "assets").mkdir()
        for name, data in files.items():
            (workdir / name).write_bytes(data)
        (workdir / "report.tex").write_text(source, encoding="utf-8")
        env = {**os.environ, "openin_any": "p", "openout_any": "p", "shell_escape": "f"}
        if kind == "tectonic":
            commands = [[path, "--untrusted", "--chatter", "minimal", "--keep-logs", "report.tex"]]
        else:
            run = [path, "-no-shell-escape", "-interaction=nonstopmode", "-halt-on-error", "report.tex"]
            commands = [run, run]  # second pass resolves the table of contents and page references
        for command in commands:
            try:
                proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                    command, cwd=workdir, env=env, capture_output=True, timeout=timeout, check=False
                )
            except subprocess.TimeoutExpired:
                raise LatexError("LaTeX compilation timed out.") from None
            if proc.returncode != 0:
                log_path = workdir / "report.log"
                log = log_path.read_text(errors="replace") if log_path.exists() else ""
                output = (proc.stdout + proc.stderr).decode(errors="replace")
                raise LatexError("LaTeX compilation failed.", _log_tail(log or output))
        pdf = workdir / "report.pdf"
        if not pdf.exists():
            raise LatexError("LaTeX did not produce a PDF.")
        return pdf.read_bytes()


def _log_tail(log: str, lines: int = 40) -> str:
    errors = [i for i, line in enumerate(log.splitlines()) if line.startswith("!") or "error:" in line]
    all_lines = log.splitlines()
    if errors:
        start = max(0, errors[0] - 2)
        return "\n".join(all_lines[start:start + lines])
    return "\n".join(all_lines[-lines:])
