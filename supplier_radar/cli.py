"""Command line: `radar run`.

By default it fetches the live CISA KEV catalog so the report reflects what is
being exploited today, and falls back to the bundled sample if the network is
unavailable. Point --kev at a file to run fully offline against a known input.
"""
from __future__ import annotations

import argparse
import os
import sys

from . import contracts, report, sources
from .pipeline import run

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)
DEFAULTS = {
    "sample_kev": os.path.join(ROOT, "data", "sample_kev.json"),
    "suppliers": os.path.join(ROOT, "data", "suppliers.csv"),
    "products": os.path.join(ROOT, "data", "supplier_products.csv"),
}


def _load_kev(kev_arg: str | None):
    """A file path if given; otherwise live CISA with the bundled sample as fallback."""
    if kev_arg:
        return sources.load_kev_file(kev_arg)
    try:
        cat = sources.fetch_kev_live()
        print(f"Fetched live KEV catalog: {cat.meta.record_count} records "
              f"(released {cat.meta.as_of})", file=sys.stderr)
        return cat
    except Exception as exc:  # noqa: BLE001 - any network failure means fall back
        print(f"Live fetch failed ({exc.__class__.__name__}); using bundled sample.", file=sys.stderr)
        return sources.load_kev_file(DEFAULTS["sample_kev"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="radar", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the pipeline and write a report")
    r.add_argument("--kev", help="path to a KEV JSON file (default: fetch live, fall back to sample)")
    r.add_argument("--suppliers", default=DEFAULTS["suppliers"])
    r.add_argument("--products", default=DEFAULTS["products"])
    r.add_argument("--out", default="out", help="output directory")
    r.add_argument("--as-of", help="date to evaluate against (YYYY-MM-DD, default: today)")
    r.add_argument("--strict", action="store_true", help="exit non-zero if any data contract is violated")
    args = parser.parse_args(argv)

    kev = _load_kev(args.kev)
    inv = sources.load_supplier_inventory(args.suppliers, args.products)

    violations = contracts.check_all(kev.vulnerabilities, inv.suppliers, inv.products)
    if violations:
        print(f"\nData contract: {len(violations)} violation(s):", file=sys.stderr)
        for v in violations:
            print(f"  [{v.dataset}/{v.rule}] {v.detail}", file=sys.stderr)
        if args.strict:
            return 2
    else:
        print("Data contract: all checks passed.", file=sys.stderr)

    result = run(inv.suppliers, inv.products, kev.vulnerabilities, kev.meta.origin, args.as_of)

    os.makedirs(args.out, exist_ok=True)
    json_path = os.path.join(args.out, "findings.json")
    html_path = os.path.join(args.out, "report.html")
    report.write_json(result, json_path)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(report.render_html(result))

    print(f"\n{result.suppliers_exposed}/{result.suppliers_total} suppliers exposed, "
          f"{len(result.findings)} findings (data as of {result.as_of}).")
    print(f"Wrote {json_path} and {html_path}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
