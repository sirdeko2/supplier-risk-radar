"""Load the inputs and record where each one came from and how fresh it is.

Two inputs:
  1. The CISA Known Exploited Vulnerabilities (KEV) catalog - the authoritative
     list of vulnerabilities that are being actively exploited in the wild.
  2. A supplier inventory: which suppliers we use, how critical each is, and
     which vendor products each one runs.

Every load returns the data plus a SourceMeta, so every downstream finding can
say exactly where it came from and as of when (traceability and freshness).
"""
from __future__ import annotations

import csv
import json
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class SourceMeta:
    """Where a dataset came from and how fresh it is."""
    name: str
    origin: str              # a URL or file path
    as_of: str               # the data's own release/collection timestamp
    retrieved_at: str        # when we loaded it
    record_count: int

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class KevCatalog:
    vulnerabilities: list[dict]
    meta: SourceMeta


@dataclass
class SupplierInventory:
    suppliers: list[dict]
    products: list[dict]     # rows of {supplier_id, vendor, product}
    suppliers_meta: SourceMeta
    products_meta: SourceMeta = field(repr=False)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_kev_file(path: str) -> KevCatalog:
    """Load the KEV catalog from a local JSON file (the bundled sample, or a saved copy)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    vulns = data.get("vulnerabilities", [])
    meta = SourceMeta("CISA KEV catalog", path, data.get("dateReleased", "unknown"),
                      _now(), len(vulns))
    return KevCatalog(vulns, meta)


def fetch_kev_live(url: str = KEV_FEED_URL, timeout: int = 30) -> KevCatalog:
    """Fetch the full live KEV catalog from CISA. Use this when running for real."""
    req = urllib.request.Request(url, headers={"User-Agent": "supplier-risk-radar"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted gov URL)
        data = json.load(resp)
    vulns = data.get("vulnerabilities", [])
    meta = SourceMeta("CISA KEV catalog (live)", url, data.get("dateReleased", "unknown"),
                      _now(), len(vulns))
    return KevCatalog(vulns, meta)


def _read_csv(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return [dict(row) for row in csv.DictReader(f)]


def load_supplier_inventory(suppliers_path: str, products_path: str) -> SupplierInventory:
    suppliers = _read_csv(suppliers_path)
    products = _read_csv(products_path)
    retrieved = _now()
    s_meta = SourceMeta("Supplier inventory", suppliers_path, retrieved, retrieved, len(suppliers))
    p_meta = SourceMeta("Supplier products", products_path, retrieved, retrieved, len(products))
    return SupplierInventory(suppliers, products, s_meta, p_meta)
