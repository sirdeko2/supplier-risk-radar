"""The pipeline: raw inputs -> dimensional model -> exposure findings.

The star schema is small but real:
  dim_supplier         one row per supplier, with a criticality derived from tier
  dim_vulnerability    one row per KEV vulnerability, with a weight from its severity signals
  bridge_supplier_product   which vendor products each supplier runs
  fact_exposure        one row per (supplier, vulnerability) where a product matches

Matching and scoring are done in SQL against DuckDB, so the logic is a query you
can read, test and later port to Redshift or Athena almost unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

import duckdb

# Business criticality by tier, and the risk bands for the final score.
TIER_CRITICALITY = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


@dataclass
class RunResult:
    findings: list[dict]
    suppliers_total: int
    suppliers_exposed: int
    as_of: str
    kev_source: str
    kev_count: int


def _build_schema(con: duckdb.DuckDBPyConnection) -> None:
    con.execute("""
        CREATE TABLE raw_supplier (supplier_id VARCHAR, supplier_name VARCHAR, tier VARCHAR,
            category VARCHAR, data_access VARCHAR, internet_facing VARCHAR);
        CREATE TABLE raw_product (supplier_id VARCHAR, vendor VARCHAR, product VARCHAR);
        CREATE TABLE raw_kev (cve_id VARCHAR, vendor VARCHAR, product VARCHAR, vuln_name VARCHAR,
            date_added DATE, due_date DATE, ransomware VARCHAR, cwes VARCHAR, description VARCHAR);
    """)


def _load_raw(con, suppliers, products, kev) -> None:
    con.executemany(
        "INSERT INTO raw_supplier VALUES (?,?,?,?,?,?)",
        [(s["supplier_id"], s["supplier_name"], s["tier"], s["category"],
          s["data_access"], s["internet_facing"]) for s in suppliers])
    con.executemany(
        "INSERT INTO raw_product VALUES (?,?,?)",
        [(p["supplier_id"], p["vendor"], p["product"]) for p in products])
    con.executemany(
        "INSERT INTO raw_kev VALUES (?,?,?,?,?,?,?,?,?)",
        [(v["cveID"], v["vendorProject"], v["product"], v["vulnerabilityName"],
          v.get("dateAdded") or None, v.get("dueDate") or None,
          v["knownRansomwareCampaignUse"], ",".join(v.get("cwes") or []),
          v.get("shortDescription", "")) for v in kev])


def _build_model(con, as_of: str) -> None:
    """Dimensions with their derived weights, then the exposure fact."""
    con.execute(f"""
        CREATE TABLE dim_supplier AS
        SELECT supplier_id, supplier_name, tier, category, data_access,
               internet_facing = 'yes' AS internet_facing,
               CASE tier WHEN 'Critical' THEN 4 WHEN 'High' THEN 3
                         WHEN 'Medium' THEN 2 ELSE 1 END AS criticality
        FROM raw_supplier;

        CREATE TABLE dim_vulnerability AS
        SELECT cve_id, vendor, product, vuln_name, date_added, due_date, cwes, description,
               ransomware = 'Known' AS ransomware,
               (due_date IS NOT NULL AND due_date < DATE '{as_of}') AS overdue,
               1 + (CASE WHEN ransomware = 'Known' THEN 2 ELSE 0 END)
                 + (CASE WHEN due_date IS NOT NULL AND due_date < DATE '{as_of}' THEN 1 ELSE 0 END)
                 AS vuln_weight
        FROM raw_kev;

        CREATE TABLE bridge_supplier_product AS SELECT * FROM raw_product;
    """)

    # The match. A product is matched to a KEV entry when the vendor matches and the
    # product strings match exactly (high confidence) or one contains the other
    # (medium confidence - e.g. "NetScaler Gateway" vs "NetScaler ADC and NetScaler Gateway").
    con.execute("""
        CREATE TABLE fact_exposure AS
        SELECT
            s.supplier_id, s.supplier_name, s.tier, s.category, s.data_access,
            s.internet_facing, s.criticality,
            v.cve_id, v.vendor, v.product AS kev_product, b.product AS supplier_product,
            v.vuln_name, v.ransomware, v.overdue, v.due_date, v.cwes, v.description,
            v.vuln_weight,
            CASE
                WHEN lower(b.product) = lower(v.product) THEN 'High'
                ELSE 'Medium'
            END AS match_confidence,
            s.criticality * v.vuln_weight AS risk_score,
            CASE
                WHEN s.criticality * v.vuln_weight >= 9 THEN 'Critical'
                WHEN s.criticality * v.vuln_weight >= 6 THEN 'High'
                WHEN s.criticality * v.vuln_weight >= 3 THEN 'Medium'
                ELSE 'Low'
            END AS risk_band
        FROM dim_supplier s
        JOIN bridge_supplier_product b USING (supplier_id)
        JOIN dim_vulnerability v
          ON lower(b.vendor) = lower(v.vendor)
         AND (lower(b.product) = lower(v.product)
              OR contains(lower(v.product), lower(b.product))
              OR contains(lower(b.product), lower(v.product)))
        ORDER BY risk_score DESC, s.supplier_id, v.cve_id
    """)


# The order risk bands sort in, worst first.
_BAND_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def run(suppliers: list[dict], products: list[dict], kev: list[dict],
        kev_source: str, as_of: str | None = None) -> RunResult:
    """Run the whole pipeline in memory and return the findings."""
    as_of = as_of or date.today().isoformat()
    con = duckdb.connect(":memory:")
    try:
        _build_schema(con)
        _load_raw(con, suppliers, products, kev)
        _build_model(con, as_of)
        cols = [c[0] for c in con.execute("SELECT * FROM fact_exposure LIMIT 0").description]
        findings = [dict(zip(cols, row)) for row in con.execute("SELECT * FROM fact_exposure").fetchall()]
        for f in findings:
            f["due_date"] = str(f["due_date"]) if f["due_date"] is not None else None
            f["source"] = "CISA KEV"
            f["as_of"] = as_of
        exposed = {f["supplier_id"] for f in findings}
        return RunResult(findings, len(suppliers), len(exposed), as_of, kev_source, len(kev))
    finally:
        con.close()
