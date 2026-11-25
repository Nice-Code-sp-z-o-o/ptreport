"""Split components.html into an overview page plus one page per component group.

components.html stays the single source (and the "all on one page" view); run this after every edit to it:
    python3 design/system/split.py
"""

from __future__ import annotations

import html
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "components.html"

GROUPS = {
    "foundations": ("foundations", "Palette, type scale and the icon set every other group is built from."),
    "actions": ("actions", "Buttons in four roles and two sizes, icon-only buttons, links."),
    "form": ("form", "Text fields, CWE combobox, selects, prose and mono text areas, target checkboxes, file input."),
    "cvss": ("cvss", "Version switch, metric option groups and the vector strip, the direction's signature move."),
    "navigation": ("navigation", "App shell bar, breadcrumb, tabs and the export menu."),
    "overlays": ("overlays", "Confirm dialog and toasts."),
    "content": ("content", "Findings table, severity badges, status labels, target chips, summary bar, empty state."),
    "evidence": ("evidence", "HTTP request and response pair, code block."),
    "feedback": ("feedback", "Inline messages, loading and progress states."),
    "report-document": ("report-document", "The light palette of the exported report: heading, facts, code."),
}

CHEVRON_LEFT = '<symbol id="i-chevron-left" viewBox="0 0 24 24"><path d="M15 6l-6 6 6 6"/></symbol>'

src = SOURCE.read_text(encoding="utf-8")

head = src[: src.index("<body>")]
sprite = re.search(r"<svg class=\"visually-hidden\".*?</svg>", src, re.S).group(0)
if "i-chevron-left" not in sprite:
    sprite = sprite.replace("<defs>", "<defs>" + CHEVRON_LEFT, 1)
footer = re.search(r"<footer.*?</footer>", src, re.S).group(0)

sections = re.findall(
    r'(<section class="ds-section" id="([^"]+)" data-section="[^"]+" data-section-label="([^"]+)".*?</section>)\s*(?=<section class="ds-section"|</main>)',
    src,
    re.S,
)
assert len(sections) == len(GROUPS), f"expected {len(GROUPS)} sections, found {len(sections)}"


def block_count(section_html: str) -> int:
    return section_html.count('class="ds-block"')


def page_head(title: str) -> str:
    return re.sub(r"<title>.*?</title>", f"<title>{html.escape(title)}</title>", head, count=1)


def topbar(current: str) -> str:
    items = [("index.html", "Overview", "index"), ("components.html", "All on one page", "all")]
    links = "".join(
        f'<a class="nav-link" href="{href}"{" aria-current=\"page\"" if key == current else ""}>{label}</a>'
        for href, label, key in items
    )
    return (
        '<header class="topbar"><a class="brand" href="index.html">ptreport</a>'
        f'<nav aria-label="Design system">{links}</nav></header>'
    )


def group_nav(current: str | None) -> str:
    links = "".join(
        f'<a href="{sid}.html"{" aria-current=\"page\"" if sid == current else ""}>{html.escape(label)}</a>'
        for _, sid, label in sections
    )
    return f'<nav class="ds-toc" aria-label="Component groups">{links}</nav>'


def as_page_section(section_html: str, sid: str) -> str:
    """The group's H2 becomes the page's only H1 and every nested heading moves up one level.

    .ds-page in components.css keeps the promoted headings at their original visual size.
    """
    section_html = re.sub(
        rf'<h2 id="{re.escape(sid)}-h">(.*?)</h2>', rf'<h1 id="{sid}-h">\1</h1>', section_html, count=1
    )
    for level in (3, 4, 5, 6):
        section_html = re.sub(rf"<(/?)h{level}\b", rf"<\1h{level - 1}", section_html)
    return section_html.replace('class="ds-section"', 'class="ds-section ds-page"', 1)


def pager(i: int) -> str:
    parts = []
    if i > 0:
        _, sid, label = sections[i - 1]
        parts.append(
            f'<a class="btn btn-secondary ds-pager-prev" href="{sid}.html">'
            f'<svg class="icon" aria-hidden="true"><use href="#i-chevron-left"/></svg>{html.escape(label)}</a>'
        )
    if i < len(sections) - 1:
        _, sid, label = sections[i + 1]
        parts.append(
            f'<a class="btn btn-secondary ds-pager-next" href="{sid}.html">{html.escape(label)}'
            f'<svg class="icon" aria-hidden="true"><use href="#i-chevron-right"/></svg></a>'
        )
    return f'<nav class="ds-pager" aria-label="Previous and next group">{"".join(parts)}</nav>'


def write(name: str, title: str, current_top: str, body: str) -> None:
    page = (
        f"{page_head(title)}<body>\n{sprite}\n{topbar(current_top)}\n<main class=\"container\">\n{body}\n</main>\n"
        f'{footer}\n<script src="components.js"></script>\n</body>\n</html>\n'
    )
    (HERE / name).write_text(page, encoding="utf-8")


rows = "".join(
    f'<li class="ds-index-row"><a class="ds-index-link" href="{sid}.html">{html.escape(label)}</a>'
    f'<span class="ds-index-count">{block_count(sec)} {"component" if block_count(sec) == 1 else "components"}</span>'
    f'<p class="ds-note">{html.escape(GROUPS[sid][1])}</p></li>'
    for sec, sid, label in sections
)
write(
    "index.html",
    "ptreport design system - Night Shift",
    "index",
    '<div class="ds-header"><h1>ptreport design system, Night Shift</h1>'
    '<p class="ds-note">Every component of the app in every state, split into groups. Built from tokens.css and '
    "components.css only.</p></div>\n"
    f'<ol class="ds-index">{rows}</ol>',
)

for i, (sec, sid, label) in enumerate(sections):
    crumbs = (
        '<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="index.html">Design system</a>'
        '<svg class="icon" aria-hidden="true"><use href="#i-chevron-right"/></svg></li>'
        f'<li aria-current="page">{html.escape(label)}</li></ol></nav>'
    )
    write(
        f"{sid}.html",
        f"{label} - ptreport design system",
        "",
        f"{crumbs}\n{group_nav(sid)}\n{as_page_section(sec, sid)}\n{pager(i)}",
    )

print(f"wrote index.html and {len(sections)} group pages")
