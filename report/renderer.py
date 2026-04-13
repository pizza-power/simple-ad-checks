"""
Single-file HTML report renderer.

Produces a self-contained, stylish HTML report with:
 - Brand colors (Blue #333366, Red #CC3333, White, Black)
 - Summary dashboard
 - Collapsible sections per check
 - Sortable tables (vanilla JS, no deps)
"""

from __future__ import annotations

import html
import datetime
from pathlib import Path

from checks import CheckResult

# ── Brand palette ────────────────────────────────────────────────────
BLUE = "#333366"
RED = "#CC3333"
WHITE = "#FFFFFF"
BLACK = "#000000"
LIGHT_GRAY = "#F4F5F7"
BORDER = "#D0D4DB"

SEVERITY_COLORS = {
    "critical": "#991B1B",
    "high": RED,
    "medium": "#B45309",
    "low": "#1D4ED8",
    "info": "#6B7280",
}

SEVERITY_BG = {
    "critical": "#FEE2E2",
    "high": "#FEE2E2",
    "medium": "#FEF3C7",
    "low": "#DBEAFE",
    "info": "#F3F4F6",
}


def _esc(val: str) -> str:
    return html.escape(str(val))


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
    bg = SEVERITY_BG.get(severity, SEVERITY_BG["info"])
    return (
        f'<span class="badge" style="background:{bg};color:{color};">'
        f"{severity.upper()}</span>"
    )


def _render_table(result: CheckResult) -> str:
    if not result.rows:
        return '<p class="empty-state">No findings.</p>'

    ths = "".join(f"<th>{_esc(h)}</th>" for h in result.headers)
    trs: list[str] = []
    for row in result.rows:
        tds = "".join(f"<td>{_esc(cell)}</td>" for cell in row)
        trs.append(f"<tr>{tds}</tr>")

    return f"""
    <table>
      <thead><tr>{ths}</tr></thead>
      <tbody>{"".join(trs)}</tbody>
    </table>"""


def render_report(domain: str, results: list[CheckResult]) -> str:
    """Return a complete self-contained HTML string."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_findings = sum(r.count for r in results)

    summary_cards = ""
    sections = ""

    for idx, r in enumerate(results):
        summary_cards += f"""
        <div class="card">
          <div class="card-count">{r.count}</div>
          <div class="card-title">{_esc(r.title)}</div>
          {_severity_badge(r.severity)}
        </div>"""

        checked = "checked" if idx == 0 else ""
        sections += f"""
        <div class="section">
          <input type="checkbox" id="toggle-{r.check_id}" class="toggle" {checked}>
          <label for="toggle-{r.check_id}" class="section-header">
            <span class="chevron"></span>
            <span class="section-title">{_esc(r.title)}</span>
            <span class="section-count">{r.count} finding{"s" if r.count != 1 else ""}</span>
            {_severity_badge(r.severity)}
          </label>
          <div class="section-body">
            <p class="section-desc">{_esc(r.description)}</p>
            {_render_table(r)}
          </div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AD Security Report &mdash; {_esc(domain)}</title>
<style>
/* ── Reset & base ──────────────────────────────────────────────── */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               "Helvetica Neue", Arial, sans-serif;
  color: {BLACK};
  background: {LIGHT_GRAY};
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}}

/* ── Header ────────────────────────────────────────────────────── */
.header {{
  background: {BLUE};
  color: {WHITE};
  padding: 2.2rem 2rem 1.8rem;
}}
.header h1 {{
  font-size: 1.6rem;
  font-weight: 700;
  letter-spacing: 0.03em;
}}
.header .subtitle {{
  opacity: 0.75;
  font-size: 0.92rem;
  margin-top: 0.35rem;
}}
.header-bar {{
  width: 60px;
  height: 4px;
  background: {RED};
  margin-top: 1rem;
  border-radius: 2px;
}}

/* ── Container ─────────────────────────────────────────────────── */
.container {{ max-width: 1200px; margin: 0 auto; padding: 1.5rem 1.2rem 3rem; }}

/* ── Summary cards ─────────────────────────────────────────────── */
.summary {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}}
.card {{
  background: {WHITE};
  border: 1px solid {BORDER};
  border-radius: 8px;
  padding: 1.2rem 1.4rem;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}}
.card-count {{
  font-size: 2rem;
  font-weight: 700;
  color: {BLUE};
}}
.card-title {{
  font-size: 0.88rem;
  font-weight: 600;
  color: #4B5563;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}}
.badge {{
  display: inline-block;
  font-size: 0.7rem;
  font-weight: 700;
  padding: 0.2em 0.6em;
  border-radius: 4px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  width: fit-content;
}}

/* ── Sections (collapsible) ────────────────────────────────────── */
.section {{
  background: {WHITE};
  border: 1px solid {BORDER};
  border-radius: 8px;
  margin-bottom: 1rem;
  overflow: hidden;
}}
.toggle {{ display: none; }}
.section-header {{
  display: flex;
  align-items: center;
  gap: 0.7rem;
  padding: 1rem 1.4rem;
  cursor: pointer;
  user-select: none;
  transition: background 0.15s;
}}
.section-header:hover {{ background: {LIGHT_GRAY}; }}
.chevron {{
  display: inline-block;
  width: 8px; height: 8px;
  border-right: 2px solid {BLUE};
  border-bottom: 2px solid {BLUE};
  transform: rotate(-45deg);
  transition: transform 0.2s;
  flex-shrink: 0;
}}
.toggle:checked + .section-header .chevron {{ transform: rotate(45deg); }}
.section-title {{ font-weight: 600; font-size: 1rem; color: {BLUE}; }}
.section-count {{ font-size: 0.82rem; color: #6B7280; margin-left: auto; }}
.section-body {{
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.35s ease;
}}
.toggle:checked ~ .section-body {{ max-height: 100000px; }}
.section-desc {{
  padding: 0 1.4rem;
  color: #6B7280;
  font-size: 0.88rem;
  margin-bottom: 1rem;
}}

/* ── Tables ────────────────────────────────────────────────────── */
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 0.88rem;
}}
th {{
  text-align: left;
  padding: 0.65rem 1rem;
  background: {BLUE};
  color: {WHITE};
  font-weight: 600;
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  cursor: pointer;
  white-space: nowrap;
  position: relative;
}}
th:hover {{ background: #2a2a55; }}
th::after {{ content: " \\2195"; font-size: 0.7em; opacity: 0.5; }}
td {{
  padding: 0.55rem 1rem;
  border-bottom: 1px solid {BORDER};
  word-break: break-word;
  max-width: 350px;
}}
tr:nth-child(even) {{ background: #FAFBFC; }}
tr:hover {{ background: #EEF0F4; }}

.empty-state {{
  text-align: center;
  padding: 2rem;
  color: #9CA3AF;
  font-style: italic;
}}

/* ── Footer ────────────────────────────────────────────────────── */
.footer {{
  text-align: center;
  padding: 2rem 1rem;
  font-size: 0.78rem;
  color: #9CA3AF;
}}
</style>
</head>
<body>

<div class="header">
  <h1>AD Security Report</h1>
  <div class="subtitle">{_esc(domain)} &mdash; Generated {_esc(now)}</div>
  <div class="subtitle">{total_findings} total finding{"s" if total_findings != 1 else ""} across {len(results)} check{"s" if len(results) != 1 else ""}</div>
  <div class="header-bar"></div>
</div>

<div class="container">
  <div class="summary">{summary_cards}</div>
  {sections}
</div>

<div class="footer">
  AD Security Report &mdash; adchecker &mdash; {_esc(now)}
</div>

<script>
// Minimal table sorting (click column headers)
document.querySelectorAll("th").forEach((th, colIdx) => {{
  th.addEventListener("click", () => {{
    const table = th.closest("table");
    const tbody = table.querySelector("tbody");
    const rows = Array.from(tbody.querySelectorAll("tr"));
    const dir = th.dataset.dir === "asc" ? "desc" : "asc";
    th.dataset.dir = dir;

    rows.sort((a, b) => {{
      const av = a.children[colIdx]?.textContent.trim() ?? "";
      const bv = b.children[colIdx]?.textContent.trim() ?? "";
      const an = parseFloat(av), bn = parseFloat(bv);
      if (!isNaN(an) && !isNaN(bn)) return dir === "asc" ? an - bn : bn - an;
      return dir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
    }});

    rows.forEach(r => tbody.appendChild(r));
  }});
}});
</script>

</body>
</html>"""


def write_report(domain: str, results: list[CheckResult], output_dir: Path) -> Path:
    """Render and write the report to disk, returning the file path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"adcheck_{domain.replace('.', '_')}_{timestamp}.html"
    path = output_dir / filename
    path.write_text(render_report(domain, results), encoding="utf-8")
    return path
