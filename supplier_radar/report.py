"""Turn findings into a findings.json file and a single-page HTML report.

The report is built for the person who has to act: it groups exposures by
supplier, leads with the worst, and every row shows its source, how fresh the
data is, and how confident the match is - so a conclusion can be challenged.
"""
from __future__ import annotations

import html
import json
from collections import Counter, defaultdict

from .pipeline import RunResult

BAND_COLOR = {"Critical": "#b42318", "High": "#b54708", "Medium": "#475467", "Low": "#98a2b3"}
BAND_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def write_json(result: RunResult, path: str) -> None:
    doc = {
        "as_of": result.as_of,
        "source": result.kev_source,
        "kev_record_count": result.kev_count,
        "suppliers_total": result.suppliers_total,
        "suppliers_exposed": result.suppliers_exposed,
        "findings": result.findings,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)


def _why(f: dict) -> str:
    bits = []
    if f["ransomware"]:
        bits.append("linked to ransomware campaigns")
    if f["overdue"]:
        bits.append(f"past CISA due date ({f['due_date']})")
    if f["data_access"] in ("PHI", "Financial", "Credentials"):
        bits.append(f"supplier handles {f['data_access']} data")
    if f["internet_facing"]:
        bits.append("internet-facing supplier")
    return "; ".join(bits) or "actively exploited in the wild"


def render_html(result: RunResult, title: str = "Supplier exposure report") -> str:
    e = html.escape
    by_supplier: dict[str, list[dict]] = defaultdict(list)
    for f in result.findings:
        by_supplier[f["supplier_id"]].append(f)
    # Worst supplier first: by its top risk score, then number of findings.
    order = sorted(by_supplier.items(),
                   key=lambda kv: (-max(x["risk_score"] for x in kv[1]), -len(kv[1])))
    bands = Counter(f["risk_band"] for f in result.findings)

    cards = "".join(
        f'<div class="card"><div class="n" style="color:{BAND_COLOR[b]}">{bands.get(b, 0)}</div>'
        f'<div>{b.lower()}</div></div>' for b in ("Critical", "High", "Medium", "Low"))
    cards += (f'<div class="card"><div class="n">{result.suppliers_exposed}'
              f'<span class="of">/{result.suppliers_total}</span></div><div>suppliers exposed</div></div>')

    sections = []
    for sid, fs in order:
        fs = sorted(fs, key=lambda x: (BAND_ORDER[x["risk_band"]], -x["risk_score"]))
        s = fs[0]
        rows = []
        for f in fs:
            conf = f["match_confidence"]
            conf_cls = "hi" if conf == "High" else "med"
            rows.append(
                f"<tr><td><span class='band' style='background:{BAND_COLOR[f['risk_band']]}'>"
                f"{f['risk_band']}</span></td>"
                f"<td><b>{e(f['cve_id'])}</b><div class='nm'>{e(f['vuln_name'])}</div></td>"
                f"<td>{e(f['vendor'])} {e(f['kev_product'])}"
                f"<div class='nm'>matched: {e(f['supplier_product'])}</div></td>"
                f"<td>{e(_why(f))}</td>"
                f"<td><span class='conf {conf_cls}'>{conf}</span></td></tr>")
        badge = (f"<span class='tag' style='background:{BAND_COLOR[s['risk_band']]}'>"
                 f"{s['risk_band']} risk</span>")
        sections.append(
            f"<div class='sup'><h2>{e(s['supplier_name'])} {badge}</h2>"
            f"<div class='meta'>{e(s['tier'])} criticality &middot; {e(s['category'])} &middot; "
            f"handles {e(s['data_access'])} &middot; {len(fs)} exposure(s)</div>"
            "<table><tr><th>Risk</th><th>Vulnerability</th><th>Product</th>"
            "<th>Why it matters</th><th>Confidence</th></tr>" + "".join(rows) + "</table></div>")

    body = "".join(sections) or "<p>No exposures found. Every supplier product is clear of the KEV catalog.</p>"
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem auto;max-width:1120px;padding:0 1rem;color:#101828}}
h1{{margin-bottom:.1rem}} .sub{{color:#667085;margin:.1rem 0 0}}
.cards{{display:flex;gap:1rem;margin:1.5rem 0;flex-wrap:wrap}}
.card{{border:1px solid #eaecf0;border-radius:10px;padding:.7rem 1.1rem;min-width:96px}}
.card .n{{font-size:1.8rem;font-weight:700}} .card .of{{font-size:1rem;color:#98a2b3;font-weight:400}}
.sup{{margin-top:1.8rem}} .sup h2{{font-size:1.1rem;margin:0 0 .15rem;display:flex;align-items:center;gap:.5rem}}
.meta{{color:#667085;font-size:.85rem;margin-bottom:.5rem}}
table{{border-collapse:collapse;width:100%;font-size:.88rem}}
th,td{{text-align:left;padding:.5rem;border-bottom:1px solid #eaecf0;vertical-align:top}}
th{{background:#f9fafb;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;color:#475467}}
.nm{{color:#667085;font-size:.8rem;margin-top:.15rem}}
.band,.tag{{color:#fff;border-radius:6px;padding:.1rem .45rem;font-size:.78rem;white-space:nowrap}}
.conf{{border-radius:6px;padding:.1rem .45rem;font-size:.78rem}}
.conf.hi{{background:#ecfdf3;color:#067647}} .conf.med{{background:#fffaeb;color:#b54708}}
.foot{{margin-top:2rem;color:#98a2b3;font-size:.8rem;border-top:1px solid #eaecf0;padding-top:.8rem}}
</style></head><body>
<h1>{e(title)}</h1>
<p class="sub">{result.suppliers_exposed} of {result.suppliers_total} suppliers run a product with an actively exploited vulnerability.</p>
<div class="cards">{cards}</div>{body}
<p class="foot">Source: {e(result.kev_source)} ({result.kev_count} records) &middot; data as of {e(result.as_of)} &middot;
risk = supplier criticality &times; vulnerability weight (ransomware and overdue raise the weight) &middot;
confidence reflects how exactly the supplier's product matched the catalog entry.</p>
</body></html>"""
