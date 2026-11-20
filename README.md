# Supplier Risk Radar

Matches a company's third-party suppliers against the **[CISA Known Exploited
Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)**
— the authoritative list of vulnerabilities being exploited in the wild — and
scores each supplier's exposure so a security team knows which vendor to call first.

It is built as a small, honest **data pipeline**: explicit sources with
provenance, a dimensional model, data-quality contracts enforced before anything
is trusted, and findings that each carry their source, freshness and match
confidence so any conclusion can be challenged.

```
CISA KEV feed ─┐
               ├─▶ data contracts ─▶ dimensional model (DuckDB) ─▶ exposure scoring ─▶ report.html + findings.json
supplier inv. ─┘   (reject bad input)   dim_* / fact_exposure        (risk + confidence)
```

## Why this exists

A vulnerability only matters here once it is *actively exploited* and you
*actually run the affected product through a supplier*. KEV gives the first
half; a supplier inventory gives the second. Joining them turns a 1,800-row
government feed into a short, ranked list of suppliers that need attention today.

## Quick start

```bash
pip install -r requirements.txt
python -m supplier_radar.cli run            # fetches the live CISA KEV catalog
open out/report.html
```

No network? Run fully offline against the bundled real sample:

```bash
python -m supplier_radar.cli run --kev data/sample_kev.json
```

By default `radar run` fetches the live KEV catalog so the report reflects what
is being exploited right now, and falls back to the bundled sample if the feed
is unreachable. The sample is a curated 16-record subset of the real catalog, so
tests and demos are deterministic and offline.

## The data model

A compact star schema, built and queried in [DuckDB](https://duckdb.org/):

| Table | Grain | Notable derived fields |
|---|---|---|
| `dim_supplier` | one supplier | `criticality` (4→1 from tier) |
| `dim_vulnerability` | one KEV CVE | `ransomware`, `overdue`, `vuln_weight` |
| `bridge_supplier_product` | supplier × product | — |
| `fact_exposure` | supplier × matched CVE | `match_confidence`, `risk_score`, `risk_band` |

Matching and scoring are done in SQL, so the logic is a query you can read and
audit — see [`docs/DATA_MODEL.md`](docs/DATA_MODEL.md) and
[`docs/SCORING.md`](docs/SCORING.md).

## Traceability and confidence

Every finding records:

- **Source** — which catalog it came from (`CISA KEV`).
- **Freshness** — the `as_of` date it was evaluated against, and the catalog's own release date.
- **Match confidence** — `High` for an exact vendor + product match, `Medium`
  when the supplier's product is a substring of a broader KEV entry
  (e.g. *NetScaler Gateway* inside *NetScaler ADC and NetScaler Gateway*).

Confidence is kept separate from risk on purpose: risk is about impact, confidence
is about how sure we are the match is real. A reviewer can filter the medium-confidence
rows and check them by hand.

## Data quality

Inputs are validated against an explicit **data contract** before the pipeline
runs (`supplier_radar/contracts.py`): required columns, allowed values for tier
and the ransomware flag, unique supplier IDs, and referential integrity between
products and suppliers. `radar run --strict` exits non-zero on any violation, so
it can gate a CI job or a scheduled run.

```bash
python -m pytest tests/ -q      # 14 tests: contracts, matching, confidence, scoring
```

## Roadmap

- [x] Local pipeline: live KEV fetch, dimensional model, scoring, HTML + JSON report
- [x] Data contracts and a test suite
- [x] Deploy on AWS: inventory + Parquet warehouse in S3, pipeline on Lambda,
      queried with Athena — see [`aws/README.md`](aws/README.md)
- [ ] AI-assisted evidence extraction: read a supplier's security questionnaire,
      pull control evidence with citations and a human-review step

## Layout

```
supplier_radar/
  sources.py     load inputs, record provenance and freshness
  contracts.py   data-quality contract enforced before the run
  pipeline.py    dimensional model + matching + scoring (DuckDB/SQL)
  report.py      findings.json and the HTML report
  cli.py         `radar run`
data/            real sample KEV + a synthetic supplier inventory
tests/           pytest suite
docs/            data model and scoring methodology
aws/             Lambda handler, Athena DDL, deploy script (S3 + Lambda + Athena)
```

The supplier inventory in `data/` is synthetic and illustrative. The KEV data is real.
