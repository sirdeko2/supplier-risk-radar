"""Data contracts: what each input must look like before we trust it.

A conclusion is only as good as the data under it, so we check the inputs
against an explicit contract first and refuse to run on data that breaks it.
Each violation is reported with the row and the rule it broke, so it can be
fixed at the source rather than silently skewing the results.
"""
from __future__ import annotations

from dataclasses import dataclass

VALID_TIERS = {"Critical", "High", "Medium", "Low"}
VALID_RANSOMWARE = {"Known", "Unknown"}
VALID_YES_NO = {"yes", "no"}

SUPPLIER_COLUMNS = {"supplier_id", "supplier_name", "tier", "category", "data_access", "internet_facing"}
PRODUCT_COLUMNS = {"supplier_id", "vendor", "product"}
KEV_FIELDS = {"cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded",
              "knownRansomwareCampaignUse"}


@dataclass
class Violation:
    dataset: str
    rule: str
    detail: str


def _missing_columns(rows: list[dict], required: set[str], dataset: str) -> list[Violation]:
    if not rows:
        return [Violation(dataset, "non_empty", "dataset has no rows")]
    present = set(rows[0].keys())
    missing = required - present
    return [Violation(dataset, "required_columns", f"missing columns: {sorted(missing)}")] if missing else []


def validate_suppliers(suppliers: list[dict], products: list[dict]) -> list[Violation]:
    out: list[Violation] = []
    out += _missing_columns(suppliers, SUPPLIER_COLUMNS, "suppliers")
    out += _missing_columns(products, PRODUCT_COLUMNS, "supplier_products")
    if out:
        return out  # structural problems first; value checks below assume columns exist

    ids = [s["supplier_id"] for s in suppliers]
    seen = set()
    for sid in ids:
        if sid in seen:
            out.append(Violation("suppliers", "unique_supplier_id", f"duplicate supplier_id: {sid}"))
        seen.add(sid)

    for s in suppliers:
        if not s["supplier_id"] or not s["supplier_name"]:
            out.append(Violation("suppliers", "no_null_keys", f"blank id or name in row: {s}"))
        if s["tier"] not in VALID_TIERS:
            out.append(Violation("suppliers", "valid_tier", f"{s['supplier_id']}: tier '{s['tier']}' not in {sorted(VALID_TIERS)}"))
        if s["internet_facing"] not in VALID_YES_NO:
            out.append(Violation("suppliers", "valid_internet_facing", f"{s['supplier_id']}: '{s['internet_facing']}'"))

    # Every product row must point at a known supplier (referential integrity).
    for p in products:
        if p["supplier_id"] not in seen:
            out.append(Violation("supplier_products", "known_supplier", f"product references unknown supplier {p['supplier_id']}"))
        if not p["vendor"] or not p["product"]:
            out.append(Violation("supplier_products", "no_null_keys", f"blank vendor or product in row: {p}"))
    return out


def validate_kev(vulnerabilities: list[dict]) -> list[Violation]:
    out: list[Violation] = []
    if not vulnerabilities:
        return [Violation("kev", "non_empty", "catalog has no vulnerabilities")]
    for v in vulnerabilities:
        missing = KEV_FIELDS - set(v.keys())
        if missing:
            out.append(Violation("kev", "required_fields", f"{v.get('cveID', '?')}: missing {sorted(missing)}"))
            continue
        if v["knownRansomwareCampaignUse"] not in VALID_RANSOMWARE:
            out.append(Violation("kev", "valid_ransomware_flag",
                                 f"{v['cveID']}: '{v['knownRansomwareCampaignUse']}'"))
    return out


def check_all(kev: list[dict], suppliers: list[dict], products: list[dict]) -> list[Violation]:
    return validate_kev(kev) + validate_suppliers(suppliers, products)
