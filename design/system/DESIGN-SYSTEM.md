# ptreport design system: Night Shift

Source of truth for every view. Specimens: `components.html` (every component in every state). Contract: `../ptreport-ui/DIRECTION.md`.
Files: `tokens.css` (fonts, tokens, report palette), `components.css` (all components), `components.js` (demo behaviour only), `fonts/`.
Read this before designing or implementing a view. A view that needs something missing adds it here and to `components.html` first.

## Modes

- **Operate** (report list, report view, finding editor): dark app palette, default `:root`.
- **Read** (exported report, HTML to PDF): always light. Put `data-theme="report"` on the document root or wrapper; the same component classes pick up the report token set. No scripts, fonts embedded or self-hosted.

## Inventory

Control heights: 32px (`btn-sm`, `segmented-sm`, `input-sm`) and 40px (default). Both grow by 8px below 640px width or on coarse pointers (touch target).
States column: D default, H hover, F focus-visible, A active, X disabled, L loading, E error, Em empty. Demo-only helper classes `is-hover`, `is-focus`, `is-active` exist so `components.html` can show them statically.

| Component | Variants | Sizes | States | Tokens | Class |
|---|---|---|---|---|---|
| Button | primary, secondary, ghost, danger (outline), danger-solid (dialog confirm only) | 32, 40 | D H F A X L | `--c-accent`, `--c-accent-ink`, `--c-raised`, `--c-control-line`, `--c-danger*`, `--h-*`, `--radius` | `.btn` `.btn-primary` `.btn-ghost` `.btn-danger` `.btn-danger-solid` `.btn-sm` |
| Icon-only button | any button variant, square, needs `aria-label` | 32, 40 | D H F A X | as button | `.btn.btn-icon` (+ `.btn-sm`) |
| Link | default, muted, external (icon + sr text) | - | D H F A | `--c-text`, `--c-muted`, `--c-accent` | `a`, `.link-muted`, `.link-ext` |
| Text input | default, mono (CWE, vector), small | 32, 40 | D H F X E | `--c-raised`, `--c-control-line`, `--c-danger` | `.input` `.is-mono` `.input-sm` |
| Textarea | prose (max 70ch), mono (PoC, HTTP, refs; max 100ch) | - | D H F X E | `--measure`, `--c-raised` | `.textarea` `.is-mono` |
| Select | native select + drawn chevron | 40 | D F X E | as input | `.select-wrap > .select` |
| Combobox (CWE) | `input[list]` + datalist, hint shows CWE name | 40 | D F E | as input | `.input.is-mono` + `datalist` |
| Checkbox / radio | bare, row card for targets, or inline option under a field (`.check-inline`) | 18px box | D H F X E, checked | `--c-accent`, `--c-control-line` | `input[type=checkbox\|radio]`, `.check`, `.check-list` |
| Segmented control (CVSS version) | radio-based; button-based (`aria-pressed`) | 32, 40 | D H F A X, selected | `--c-accent`, `--c-control-line` | `.segmented` `.seg` `.seg-btn` `.segmented-sm` |
| CVSS metric group | rows of segmented choices per metric, grouped as FIRST | 32 | D H F X, missing | as segmented | `.cvss-groups` `.cvss-group` `.cvss-grid` `.cvss-metric` `.cvss-metric-name` `.is-missing` |
| Field label, help, error | label above, hint, error with icon | - | D E | `--c-muted`, `--c-danger` | `.field` `.hint` `.field-error` `.req` |
| File input | dashed drop-style field | 40 | D H X E | as input | `.file-input` |
| Tabs | `button[role=tab]` or `a[aria-current]`; accent marker slides on transform | 40 | D H F X, selected | `--c-accent`, `--c-line` | `.tabs` `.tab` `.tab-count` `.tab-panel` |
| Breadcrumb | ordered list, chevron icons, current page mono ID | - | D H F | `--c-muted` | `.crumbs` |
| Top navigation | brand + nav links, current page marker | 52 | D H F, current | `--c-surface`, `--c-accent` | `.topbar` `.brand` `.nav-link` |
| CVSS chip | outlined chip: score (mono, bold) + CVSS rating, 3px rating-coloured edge; `-lg` in the calculator | 22px, 30px | none/low/medium/high/critical | `--c-sev-*`, `--c-muted` for None | `.cvss-chip` `.cv-<rating>` `.cvss-chip-score` `.cvss-chip-rating` |
| History list | rows: date, author, text; inline edit in `details`; delete | one row per entry | D, open (edit) | `--c-line`, `--c-surface` | `.history-list` `.history-row` `.history-main` `.history-edit` `.grid-history` `.grid-version-4` |
| Screenshot card | thumbnail (contain, 16:10), caption field + save, size/type, delete | grid of 240px+ cards | D H F, empty | `--c-surface`, `--c-line`, `--radius-lg` | `.shot-list` `.shot` `.shot-img` `.shot-caption` `.shot-meta` |
| Dropdown menu (Export) | `details` + panel, items with icon, separator | 40 rows | D H F X, open | `--shadow-overlay` | `.dropdown` `.dropdown-menu` (`.align-start` when the trigger sits at the left edge) `.menu-item` `.menu-sep` |
| Modal / confirm | native `dialog.showModal()` | 32rem | open | `--shadow-overlay`, `--c-overlay` | `.modal` `.modal-body` `.modal-foot` |
| Toast | floating `.flash` in a stack | 24rem | success, error | as flash | `.toast-stack` + `.flash` |
| Flash message | page-level, tinted full border, icon | - | success, error | `--c-ok`, `--c-danger` | `.flash` `.flash-success` `.flash-error` `.flash-body` |
| Table (findings) | dense, ID mono, severity, score, vector strip, CWE, target chips, status, order controls | 13px text | D H, loading, Em | `--c-line`, `--c-raised` | `.table-wrap` `.table` `.col-*` `.order-ctrl` |
| Severity badge | critical, high, medium, low, info (tint + text + 4-bar level mark) | 22px | - | `--c-sev-*`, `--sev-tint` | `.sev` `.sev-critical` ... |
| Status label | open, fixed, risk_accepted, false_positive (drawn icon + text) | - | - | `--c-st-*` | `.status` `.status-open` ... |
| Chip (target) | plain, with remove button | 24 | D H F | `--c-raised` | `.chip` `.chip-remove` `.chips` |
| Severity summary bar | SVG segments + legend with counts; small variant in list rows | 12px, 8px | zero count | `--c-sev-*` | `.sev-bar` `.sev-bar-svg` `.seg-*` `.sev-legend` `.sev-bar-sm` |
| List row (report list) | title, client, dates, prefix, mini bar | - | D H | `--c-surface` | `.rows` `.row` `.row-title` `.row-meta` `.row-count` |
| Empty state | icon, heading, sentence, one action | - | - | `--c-control-line` | `.empty` |
| HTTP evidence | request/response pair, mono, scroll both ways, focusable | max 320px | D F | `--c-ground` | `.evidence` `.http-pair` `.http-pane` `pre.http` |
| Code block / inline code | block scrolls, never wraps | max 320px | D F | as above | `pre.code`, `code` |
| **CVSS vector strip (signature)** | compact (table), large (calculator summary, with group names and value names) | 20px cell; large auto | tone 0 to 3 | `--vec-0..3-bg/ink/line` | `.vec` `.vec-group` `.vec-cell[data-level]` `.vec-lg`, summary: `.vec-summary` `.vec-score` `.vector-text` |
| Spinner | in button or inline; transform rotation | 16 | L | - | `.spinner` |

Not needed by this app (do not build speculatively): search field, switch, stepper, pagination, drawer, popover, bottom sheet, tooltip (cells use native `title`), cookie banner, card (product/article), price block, skeleton, media frames, progress bar, countdown.

### Vector strip rules

- Markup: `ul.vec[aria-label=vector] > li.vec-group > (span.vec-group-name, ul.vec-cells > li.vec-cell[data-level][title] > span.vec-k + span.vec-v)`. Groups: 3.1 Exploitability (AV AC PR UI), Scope (S), Impact (C I A); 4.0 Exploitability (AV AC AT PR UI), Vulnerable system (VC VI VA), Subsequent system (SC SI SA). Compact shows `AV:N`; large shows key above the value name.
- `data-level` 0 to 3 = how much the value raises the score within its metric (0 none, 3 highest). Computed server-side from the metric value weights, never typed in a template by hand. Tone is lightness only, no hue. The demo uses: AV N3 A2 L1 P0; AC L3 H1; AT N3 P1; PR N3 L2 H1; UI N3 P2 A1 / R1; S U0 C2; C/I/A (and VC.. SA) H3 L1 N0. [TO CONFIRM: final level mapping with the score logic owner.]
- 3.0 and 2.0 vectors use the same cell; their group split is an open point.

## Tokens (`tokens.css`)

- Palette app: `--c-ground #0F1418`, `--c-surface #161D23`, `--c-raised #1C252D`, `--c-line #26313A`, `--c-control-line #667784` (3.4:1, control borders), `--c-text #E3E8EC`, `--c-muted #93A1AC` (6.4:1 on surface, 5.9:1 on raised), `--c-accent #E0A33A`, `--c-accent-ink #1A1203`, `--c-accent-hover`, `--c-overlay`.
- Severity: `--c-sev-critical #FF6F82`, `-high #FF9A5A`, `-medium #EBCB4F`, `-low #6FD0A0`, `-info #86B2EA`; each at least 5:1 as text on its 14% tint over surface. `--sev-tint` sets tint strength. Meaning is also carried by the label text and the 4-bar level mark.
- Status and feedback: `--c-ok`, `--c-danger`, `--c-danger-strong(-ink)`, `--c-st-open|fixed|accepted|false`.
- Vector tones: `--vec-0..3-bg|ink|line`.
- Type: `--font-ui` Hanken Grotesk (variable 100-900), `--font-mono` JetBrains Mono; `--fs-xs 12px`, `-sm 13`, `-md 15`, `-lg 18`, `-xl 23`, `-2xl 30`; `--lh-tight|ui|prose`; `--fw-*`; `--measure 70ch`. Tabular numerals on body.
- Space: `--sp-1..8` = 4, 8, 12, 16, 24, 32, 48, 72px.
- Shape: `--radius 4px` (every control, badge, chip, cell), `--radius-lg 8px` (panels, tables, menus, dialogs).
- Controls: `--h-sm 32`, `--h-md 40`, `--icon 16`, `--icon-stroke 1.75`.
- Focus ring: `--focus-ring` (2px ground gap + 2px accent). Selection: accent background, accent ink text. Scrollbar: `--scrollbar-thumb/track`. Caret: accent.
- Motion: `--ease-out`, `--dur-fast`, `--dur`. Only transform and opacity animate; colour changes are instant. `prefers-reduced-motion` disables all animation.
- Report palette: `[data-theme="report"]` overrides the same names with paper `#FFF`, ink `#151B20`, muted `#4A5762`, darker severity colours (each at least 5:1 on white and on its tint) and a reversed vector ramp (level 3 = dark cell).
- Fonts load from `fonts/` by relative path in `tokens.css`; when the CSS moves into `static/`, move `fonts/` with it. No CDN.

## Rules

1. One shape per family: buttons, icon buttons, inputs, selects, segmented, chips, badges and vector cells share `--radius`. No pill or round control exists (radio is the single native-shape exception).
2. Mono only for data: IDs, CWE ids, vectors and cells, scores, targets' addresses, HTTP, code. Never labels or headings.
3. Severity colour only for severity. Accent only for selection, focus and primary action. Amber is not a warning colour; use `--c-danger` for errors.
4. Icons: inline SVG symbols, 24px grid, one stroke weight, `aria-hidden`; icon-only buttons carry `aria-label`. No emoji or glyph icons; arrows are drawn (`arrow-up`, `arrow-down`).
5. CSP (`script-src 'self'; style-src 'self'`): no `style=` attributes, no inline scripts, no `data:` URLs in CSS. Proportions are SVG attributes (summary bar); state is classes or `data-level`. Scripts live in files.
6. Surfaces: flat, 1px lines and one step of lightness; shadows only on overlays (offset + blur). No card inside a card: `.panel` is a single level, groups use headings and spacing.
7. Text areas: prose at most 70ch, mono at most 100ch.
8. Disabled controls use dashed border and muted text (contrast preserved), never opacity.
9. Selected state marker (tabs, nav) is a clipped pseudo-element arriving on `transform`.
10. Copy: headings carry themselves (no kickers, no section numbers), UI strings are the app's language (components shown in English like the current app; report content stays in the report language).

## Mapping to current app (`src/ptreport/static/app.css`)

Old class to new class. Names kept where the concept is unchanged.

| Current | New |
|---|---|
| `:root` light/dark variables `--bg --surface --surface-2 --border --text --muted --primary --danger --ok --focus --sev-*` | `tokens.css` `--c-*`; one dark palette, no `prefers-color-scheme` switch; report palette via `data-theme="report"` |
| `.topbar`, `.brand`, `.brand-mark`, `.topbar nav a` | `.topbar`, `.brand` (plain wordmark, brand-mark dropped), `.nav-link` with `aria-current="page"` |
| `.container`, `.footer` | `.container`, `.footer` |
| `.card`, `.card.narrow`, `.danger-zone` | `.panel` (no shadow), danger zone = `.panel` with a `.btn-danger` |
| `.page-head`, `.section-head`, `.actions` | `.page-head`, `.section-head`, `.cluster` |
| `.crumbs` with " / " text | `nav.crumbs > ol` with chevron icons |
| `.btn`, `.btn-primary`, `.btn-danger`, `.btn-ghost`, `.btn-sm`, `.btn-icon` | same names; `.btn-icon` now square at control height; text arrows in `post_button('↑')` become `svg arrow-up/down` with `aria-label` |
| `.table`, `.num`, `.order-cell`, `.pill` | `.table-wrap > .table`, `.col-num`, `.col-order`, `.chip` (source tag: `.chip.pill-src`) |
| `.sev`, `.sev-*` filled pills | `.sev` tinted badge with level mark |
| `.sev-summary`, `.sev-tile*` (five tiles with count) | `.sev-bar` (SVG bar + legend); tiles removed |
| status as plain text | `.status .status-<key>` |
| `.flash`, `.flash-success`, `.flash-error` | same names with icon and `.flash-body`; floating variant `.toast-stack` |
| `.form .field`, `label`, `.hint`, `.field-error`, `.has-error`, `.req` | `.field`, `.hint`, `.field-error`; error state is `aria-invalid="true"` on the control, `.has-error` dropped |
| `.field input/select/textarea`, `.mono` | `.input`, `.select-wrap > .select`, `.textarea`, `.is-mono` |
| `.grid-2`, `.grid-3`, `.grid-2.tight` | `.grid-2`, `.grid-3` |
| `.form-actions`, `.sticky-actions` (blur backdrop) | `.cluster` in a sticky bar on `--c-surface` (no blur) |
| `.checklist`, `.check` | `.check-list`, `.check` |
| `.dropdown`, `.dropdown-menu`, bare `a` | `.dropdown`, `.dropdown-menu`, `.menu-item` |
| `.segmented`, `.seg` | `.segmented`, `.seg` |
| `.cvss-group`, `.cvss-group-title` (uppercase), `.cvss-grid`, `.cvss-metric-name`, `.cvss-opt`, `.cvss-metric.missing` | `.cvss-group > h3`, `.cvss-grid`, `.cvss-metric-name`, `.seg-btn` in `.segmented.segmented-sm`, `.cvss-metric.is-missing` |
| `.cvss-result`, `.cvss-score`, `.note`, `.err` | `.vec-summary` (`.vec-score`, large `.vec-lg` strip, `.vector-text`); errors via `.field-error` |
| table cell with plain vector text | `.cvss-cell` with compact `.vec` strip (new) |
| `.evidence`, `.http-pair`, `pre.http` (wrapped) | `.evidence`, `.http-pair`, `.http-pane`, `pre.http` (no wrap, scroll, `tabindex=0`) |
| `.empty` | `.empty` with icon and action |
| `window.confirm` via `post_button` | `dialog.modal` (needs a small script file; `app.js` change is outside this system) |
| `code` | `code` |
| `h4` uppercase labels | `h4` plain (no uppercase) |

`report.css` (exported document) is replaced by the report token set plus `.sev`, `.status`, `.table`, `pre.code`, `.vec`, `.sev-bar`.

## Open points

- Level mapping for vector cells and 3.0/2.0 grouping need sign-off (see above).
- `brand` is a plain text wordmark; no mark exists yet.
- Calculator summary score size (23px) is deliberately small to stay out of the hero-metric pattern.
- Real-world 44px touch targets: 40px buttons become 44px at narrow widths, 32px become 40px; chips and chip-remove stay small (secondary targets).
- Toast and dialog need `components.js`-style behaviour in `static/app.js`; not written here.

## Pages

`components.html` is the single source and the "all on one page" view. `python3 design/system/split.py` generates
`index.html` (overview of the groups) and one page per group (`foundations.html`, `actions.html`, `form.html`,
`cvss.html`, `navigation.html`, `overlays.html`, `content.html`, `evidence.html`, `feedback.html`,
`report-document.html`). Edit `components.html`, then rerun the script; never edit the generated pages.
On a group page the group heading becomes the only H1 and nested headings move up one level; `.ds-page` keeps them
at their original visual size.
