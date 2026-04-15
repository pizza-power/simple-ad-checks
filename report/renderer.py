"""
Single-file HTML report renderer.

Produces a self-contained, stylish HTML report with:
 - Brand colors (Blue #333366, Red #CC3333, White, Black)
 - Summary dashboard
 - Collapsible sections per check
 - Sortable tables (vanilla JS, no deps)
 - Multi-domain tab navigation (when >1 domain)
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

_PALETTE = {
    "blue": BLUE,
    "red": RED,
    "white": WHITE,
    "black": BLACK,
    "light_gray": LIGHT_GRAY,
    "border": BORDER,
}

# ── Shared CSS (uses %% formatting to avoid f-string brace escaping) ─
_BASE_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
               "Helvetica Neue", Arial, sans-serif;
  color: %(black)s;
  background: %(light_gray)s;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}

.header {
  background: %(blue)s;
  color: %(white)s;
  padding: 2.2rem 2rem 1.8rem;
}
.header h1 {
  font-size: 1.6rem;
  font-weight: 700;
  letter-spacing: 0.03em;
}
.header .subtitle {
  opacity: 0.75;
  font-size: 0.92rem;
  margin-top: 0.35rem;
}
.header-bar {
  width: 60px;
  height: 4px;
  background: %(red)s;
  margin-top: 1rem;
  border-radius: 2px;
}

.container { max-width: 1200px; margin: 0 auto; padding: 1.5rem 1.2rem 3rem; }

.summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}
.card {
  background: %(white)s;
  border: 1px solid %(border)s;
  border-radius: 8px;
  padding: 1.2rem 1.4rem;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}
.card-count {
  font-size: 2rem;
  font-weight: 700;
  color: %(blue)s;
}
.card-title {
  font-size: 0.88rem;
  font-weight: 600;
  color: #4B5563;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.badge {
  display: inline-block;
  font-size: 0.7rem;
  font-weight: 700;
  padding: 0.2em 0.6em;
  border-radius: 4px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  width: fit-content;
}

.section {
  background: %(white)s;
  border: 1px solid %(border)s;
  border-radius: 8px;
  margin-bottom: 1rem;
  overflow: hidden;
}
.toggle { display: none; }
.section-header {
  display: flex;
  align-items: center;
  gap: 0.7rem;
  padding: 1rem 1.4rem;
  cursor: pointer;
  user-select: none;
  transition: background 0.15s;
}
.section-header:hover { background: %(light_gray)s; }
.chevron {
  display: inline-block;
  width: 8px; height: 8px;
  border-right: 2px solid %(blue)s;
  border-bottom: 2px solid %(blue)s;
  transform: rotate(-45deg);
  transition: transform 0.2s;
  flex-shrink: 0;
}
.toggle:checked + .section-header .chevron { transform: rotate(45deg); }
.section-title { font-weight: 600; font-size: 1rem; color: %(blue)s; }
.section-count { font-size: 0.82rem; color: #6B7280; margin-left: auto; }
.section-body {
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.35s ease;
}
.toggle:checked ~ .section-body { max-height: 100000px; }
.section-desc {
  padding: 0 1.4rem;
  color: #6B7280;
  font-size: 0.88rem;
  margin-bottom: 1rem;
}

table {
  width: 100%%;
  border-collapse: collapse;
  font-size: 0.88rem;
}
th {
  text-align: left;
  padding: 0.65rem 1rem;
  background: %(blue)s;
  color: %(white)s;
  font-weight: 600;
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  cursor: pointer;
  white-space: nowrap;
  position: relative;
}
th:hover { background: #2a2a55; }
th::after { content: " \\2195"; font-size: 0.7em; opacity: 0.5; }
td {
  padding: 0.55rem 1rem;
  border-bottom: 1px solid %(border)s;
  word-break: break-word;
  max-width: 350px;
}
tr:nth-child(even) { background: #FAFBFC; }
tr:hover { background: #EEF0F4; }

.empty-state {
  text-align: center;
  padding: 2rem;
  color: #9CA3AF;
  font-style: italic;
}

tr.t0 { background: #FEF3C7 !important; border-left: 3px solid #DC2626; }
tr.t0:hover { background: #FDE68A !important; }
.t0-diamond { color: #DC2626; font-weight: 700; margin-right: 0.3em; }
.t0-legend {
  display: flex;
  align-items: center;
  gap: 0.4em;
  font-size: 0.8rem;
  color: #6B7280;
  margin-top: 0.5rem;
  padding: 0 1.4rem 1rem;
}

.footer {
  text-align: center;
  padding: 2rem 1rem;
  font-size: 0.78rem;
  color: #9CA3AF;
}
""" % _PALETTE

# ── Tab-specific CSS ─────────────────────────────────────────────────
_TAB_CSS = """
.tab-bar {
  max-width: 1200px;
  margin: 0 auto;
  display: flex;
  gap: 0;
  padding: 0 1.2rem;
  overflow-x: auto;
  background: %(white)s;
  border-bottom: 2px solid %(border)s;
}
.tab-btn {
  padding: 0.85rem 1.5rem;
  cursor: pointer;
  border: none;
  background: transparent;
  font-family: inherit;
  font-size: 0.88rem;
  font-weight: 600;
  color: #6B7280;
  border-bottom: 3px solid transparent;
  margin-bottom: -2px;
  white-space: nowrap;
  transition: color 0.15s, border-color 0.15s;
}
.tab-btn:hover { color: %(blue)s; }
.tab-btn.active {
  color: %(blue)s;
  border-bottom-color: %(red)s;
}
.tab-count {
  display: inline-block;
  font-size: 0.72rem;
  font-weight: 700;
  background: %(light_gray)s;
  color: #6B7280;
  padding: 0.15em 0.5em;
  border-radius: 10px;
  margin-left: 0.4rem;
  vertical-align: middle;
}
.tab-btn.active .tab-count {
  background: %(blue)s;
  color: %(white)s;
}
.tab-content { display: none; }
.tab-content.active { display: block; }
""" % _PALETTE

# ── JS snippets (plain strings — no escaping needed) ─────────────────
_SORT_JS = """
document.querySelectorAll("th").forEach(th => {
  th.addEventListener("click", () => {
    const table = th.closest("table");
    const tbody = table.querySelector("tbody");
    const rows = Array.from(tbody.querySelectorAll("tr"));
    const colIdx = Array.from(th.parentElement.children).indexOf(th);
    const dir = th.dataset.dir === "asc" ? "desc" : "asc";
    th.dataset.dir = dir;

    rows.sort((a, b) => {
      const av = a.children[colIdx]?.textContent.trim() ?? "";
      const bv = b.children[colIdx]?.textContent.trim() ?? "";
      const an = parseFloat(av), bn = parseFloat(bv);
      if (!isNaN(an) && !isNaN(bn)) return dir === "asc" ? an - bn : bn - an;
      return dir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
    });

    rows.forEach(r => tbody.appendChild(r));
  });
});
"""

_TAB_JS = """
document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.target).classList.add("active");
  });
});
"""


# ── Helpers ──────────────────────────────────────────────────────────

def _esc(val: str) -> str:
    return html.escape(str(val))


def _domain_id(domain: str) -> str:
    """Sanitize a domain name into a safe HTML id fragment."""
    return domain.replace(".", "_").replace(" ", "_").lower()


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
    t0_flags = result.extra.get("tier_zero", [])
    t0_col = result.extra.get("tier_zero_col", 0)
    has_any_t0 = any(t0_flags)

    trs: list[str] = []
    for i, row in enumerate(result.rows):
        is_t0 = i < len(t0_flags) and t0_flags[i]
        row_cls = ' class="t0"' if is_t0 else ""

        if is_t0:
            cells: list[str] = []
            for j, cell in enumerate(row):
                if j == t0_col:
                    cells.append(
                        f'<td><span class="t0-diamond">\u25c6</span>{_esc(cell)}</td>'
                    )
                else:
                    cells.append(f"<td>{_esc(cell)}</td>")
            tds = "".join(cells)
        else:
            tds = "".join(f"<td>{_esc(cell)}</td>" for cell in row)

        trs.append(f"<tr{row_cls}>{tds}</tr>")

    legend = ""
    if has_any_t0:
        legend = (
            '<div class="t0-legend">'
            '<span class="t0-diamond">\u25c6</span>'
            " = Tier Zero asset (High Value Target in BloodHound)"
            "</div>"
        )

    return f"""
    <table>
      <thead><tr>{ths}</tr></thead>
      <tbody>{"".join(trs)}</tbody>
    </table>
    {legend}"""


def _render_domain_content(
    results: list[CheckResult], id_prefix: str = ""
) -> tuple[str, str]:
    """Build summary-card HTML and collapsible-section HTML for one domain.

    Returns ``(summary_cards, sections)``.
    *id_prefix* is prepended to toggle IDs so multiple domains can coexist
    in a single document without ID collisions.
    """
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
        toggle_id = f"toggle-{id_prefix}{r.check_id}"
        sections += f"""
        <div class="section">
          <input type="checkbox" id="{toggle_id}" class="toggle" {checked}>
          <label for="{toggle_id}" class="section-header">
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

    return summary_cards, sections


# ── Single-domain report (backward compatible) ──────────────────────

def render_report(domain: str, results: list[CheckResult]) -> str:
    """Return a complete self-contained HTML string for a single domain."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_findings = sum(r.count for r in results)
    summary_cards, sections = _render_domain_content(results)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AD Security Report &mdash; {_esc(domain)}</title>
<style>{_BASE_CSS}</style>
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

<script>{_SORT_JS}</script>

</body>
</html>"""


# ── Multi-domain tabbed report ───────────────────────────────────────

def render_multi_domain_report(
    domain_results: dict[str, list[CheckResult]],
) -> str:
    """Return a self-contained HTML report with per-domain tabs."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    domains = list(domain_results.keys())
    grand_total = sum(
        sum(r.count for r in results) for results in domain_results.values()
    )

    # If there's only one domain, fall back to the simpler layout
    if len(domains) == 1:
        return render_report(domains[0], domain_results[domains[0]])

    # Build tab buttons and per-domain content panels
    tab_buttons = ""
    tab_panels = ""

    for i, (domain, results) in enumerate(domain_results.items()):
        did = _domain_id(domain)
        active = " active" if i == 0 else ""
        domain_total = sum(r.count for r in results)

        tab_buttons += (
            f'<button class="tab-btn{active}" data-target="tab-{did}">'
            f"{_esc(domain)} "
            f'<span class="tab-count">{domain_total}</span>'
            f"</button>\n"
        )

        summary_cards, sections = _render_domain_content(
            results, id_prefix=f"{did}-"
        )
        tab_panels += f"""
    <div id="tab-{did}" class="tab-content{active}">
      <div class="summary">{summary_cards}</div>
      {sections}
    </div>"""

    subtitle_domains = ", ".join(_esc(d) for d in domains)
    tab_css = _TAB_CSS
    tab_js = _TAB_JS

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AD Security Report &mdash; {subtitle_domains}</title>
<style>
{_BASE_CSS}
{tab_css}
</style>
</head>
<body>

<div class="header">
  <h1>AD Security Report</h1>
  <div class="subtitle">{subtitle_domains} &mdash; Generated {_esc(now)}</div>
  <div class="subtitle">{grand_total} total finding{"s" if grand_total != 1 else ""} across {len(domains)} domain{"s" if len(domains) != 1 else ""}</div>
  <div class="header-bar"></div>
</div>

<div class="tab-bar">
{tab_buttons}</div>

<div class="container">
{tab_panels}
</div>

<div class="footer">
  AD Security Report &mdash; adchecker &mdash; {_esc(now)}
</div>

<script>
{_SORT_JS}
{tab_js}
</script>

</body>
</html>"""


# ── File writers ─────────────────────────────────────────────────────

def write_report(domain: str, results: list[CheckResult], output_dir: Path) -> Path:
    """Render and write a single-domain report to disk."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"adcheck_{domain.replace('.', '_')}_{timestamp}.html"
    path = output_dir / filename
    path.write_text(render_report(domain, results), encoding="utf-8")
    return path


def write_multi_domain_report(
    domain_results: dict[str, list[CheckResult]], output_dir: Path
) -> Path:
    """Render and write a multi-domain tabbed report to disk."""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"adcheck_combined_{timestamp}.html"
    path = output_dir / filename
    path.write_text(
        render_multi_domain_report(domain_results), encoding="utf-8"
    )
    return path
