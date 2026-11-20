# Data model

The pipeline builds a small star schema in DuckDB. The design goal is that the
matching and scoring logic lives in SQL a reviewer can read, and that the fact
table has a clear grain: **one row per (supplier, matched vulnerability)**.

## Dimensions

### `dim_supplier`
One row per supplier, from `data/suppliers.csv`.

| column | meaning |
|---|---|
| `supplier_id` | primary key |
| `supplier_name`, `category`, `data_access` | descriptive |
| `tier` | business criticality: Critical / High / Medium / Low |
| `internet_facing` | boolean, derived from a yes/no column |
| `criticality` | integer derived from tier: Critical=4, High=3, Medium=2, Low=1 |

### `dim_vulnerability`
One row per CVE in the KEV catalog.

| column | meaning |
|---|---|
| `cve_id` | primary key |
| `vendor`, `product` | the affected product, as CISA names it |
| `ransomware` | boolean: is it linked to known ransomware campaigns |
| `overdue` | boolean: is `due_date` before the run's `as_of` date |
| `vuln_weight` | `1 + 2*ransomware + 1*overdue` → range 1–4 |

## Bridge

### `bridge_supplier_product`
The many-to-many link: which vendor products each supplier runs
(`data/supplier_products.csv`). A supplier can run several products; a product
can be run by several suppliers.

## Fact

### `fact_exposure`
Built by joining suppliers → their products → matching vulnerabilities. The join
condition is where matching happens:

```sql
JOIN dim_vulnerability v
  ON lower(b.vendor) = lower(v.vendor)            -- vendor must match
 AND (lower(b.product) = lower(v.product)         -- exact product  -> High confidence
      OR contains(lower(v.product), lower(b.product))  -- or substring either way
      OR contains(lower(b.product), lower(v.product)))  -> Medium confidence
```

Requiring the vendor to match prevents false positives where two vendors reuse a
common product word (e.g. "Gateway"). Each surviving row gets a `match_confidence`,
a numeric `risk_score`, and a `risk_band`. See [SCORING.md](SCORING.md).

## Why DuckDB

It is an in-process analytical database: no server to run, reads CSV/JSON
directly, and speaks standard SQL. The same `dim_*` / `fact_*` model and the same
queries port to a warehouse (Redshift, Snowflake, Athena) with almost no change,
which is the intended next step for the AWS deployment.
