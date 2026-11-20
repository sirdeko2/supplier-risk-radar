"""AWS Lambda entry point for Supplier Risk Radar.

On each invocation it:
  1. reads the supplier inventory from S3  (s3://$DATA_BUCKET/inputs/)
  2. fetches the live CISA KEV catalog
  3. builds the star schema and writes every table to Parquet
  4. uploads the Parquet to s3://$DATA_BUCKET/warehouse/<table>/  (Athena reads these)
  5. writes findings.json and report.html to s3://$DATA_BUCKET/reports/

Trigger it on a schedule with EventBridge to keep the warehouse current.
The heavy lifting is the same `supplier_radar` package that runs locally - only
the input/output plumbing is cloud-specific, which is the point: the pipeline
did not have to change to run in AWS.
"""
from __future__ import annotations

import os
import tempfile

import boto3

from supplier_radar import contracts, report, sources
from supplier_radar.pipeline import WAREHOUSE_TABLES, export_warehouse

s3 = boto3.client("s3")


def _download(bucket: str, key: str, dest: str) -> str:
    s3.download_file(bucket, key, dest)
    return dest


def handler(event, context):  # noqa: ARG001 - Lambda signature
    bucket = os.environ["DATA_BUCKET"]
    strict = os.environ.get("STRICT", "false").lower() == "true"
    work = tempfile.mkdtemp()

    # 1. inputs from S3
    suppliers_csv = _download(bucket, "inputs/suppliers.csv", f"{work}/suppliers.csv")
    products_csv = _download(bucket, "inputs/supplier_products.csv", f"{work}/supplier_products.csv")
    inv = sources.load_supplier_inventory(suppliers_csv, products_csv)

    # 2. live KEV
    kev = sources.fetch_kev_live()

    # 3. data contract
    violations = contracts.check_all(kev.vulnerabilities, inv.suppliers, inv.products)
    if violations and strict:
        raise RuntimeError(f"{len(violations)} data-contract violation(s); aborting (STRICT=true)")

    # 4. build + export the warehouse to Parquet
    wh = f"{work}/warehouse"
    result = export_warehouse(inv.suppliers, inv.products, kev.vulnerabilities, kev.meta.origin, wh)

    # 5. upload Parquet under one prefix per table (Athena external tables point at these)
    for table in WAREHOUSE_TABLES:
        s3.upload_file(f"{wh}/{table}.parquet", bucket, f"warehouse/{table}/{table}.parquet")

    # reports
    findings_path = f"{work}/findings.json"
    report.write_json(result, findings_path)
    s3.upload_file(findings_path, bucket, "reports/findings.json")
    html_path = f"{work}/report.html"
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(report.render_html(result))
    s3.upload_file(html_path, bucket, "reports/report.html",
                   ExtraArgs={"ContentType": "text/html"})

    summary = {
        "suppliers_total": result.suppliers_total,
        "suppliers_exposed": result.suppliers_exposed,
        "findings": len(result.findings),
        "kev_records": result.kev_count,
        "as_of": result.as_of,
        "violations": len(violations),
        "warehouse_prefix": f"s3://{bucket}/warehouse/",
        "report": f"s3://{bucket}/reports/report.html",
    }
    print(summary)
    return summary
