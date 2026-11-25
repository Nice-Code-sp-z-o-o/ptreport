# Direction: Night Shift

Chosen 2026-11-25 at gate 1.

## Thesis

A dark operator shell that sits next to Burp Suite and a terminal without looking like either: matte surfaces,
no glow, no neon. The pentester reads the state of a report at a glance and enters a finding fast.

## Surface modes

- App screens (report list, report view, finding editor): **Operate**. Standard web controls, the world lends
  type, palette, density and one signature move only.
- Exported report (HTML -> PDF): **Read**. Always light, its own palette derived from the same tokens.

## World

- Type: **Hanken Grotesk** (UI and text, self-hosted, latin + latin-ext for Polish), **JetBrains Mono** strictly for
  data: CVSS vectors, finding IDs, HTTP messages, addresses, code. Never as a "technical" costume.
- Palette (app): ground `#0F1418`, surface `#161D23`, raised `#1C252D`, line `#26313A`, text `#E3E8EC`,
  muted text (measured to 4.5:1 on surface), accent muted amber `#E0A33A` for selection, focus and primary action.
- Severity colours carry meaning only and differ in lightness, not hue alone: Critical, High, Medium, Low, Info.
- Material: matte, flat surfaces separated by 1px lines and one step of lightness. Shadows only on overlays,
  with offset and blur, never a coloured halo.
- Density: compact rows (finding tables), comfortable text fields in the editor.

## Signature move

**The CVSS vector as a metric-cell strip.** Every finding row shows its vector as a row of small cells, one per base
metric, each cell labelled with the metric value and toned by how much it raises the score. Readable in a table
without expanding, and the same strip is the calculator's summary in the editor. It is the only ornament.

## Cost (accepted)

Two palettes to maintain (dark app, light report). Long descriptions on a dark ground tire the eye, so text areas
use the raised surface and a 65-75ch measure.

## Rejected

- Audit Desk (light, calm): least distinctive, reads as any SaaS tool.
- Case File (master-detail): editor too narrow next to the list on laptop widths.

## References

- 169 GitHub Advisory Database: severity label, id and CWE in one dense row.
- 168 FIRST CVSS 4.0 calculator: metric groups as rows of segmented choices with live score.
- 134 Linear: calm density in a dark working tool.
