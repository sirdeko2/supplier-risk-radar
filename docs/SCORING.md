# Scoring methodology

The score answers one question: **if I can only act on a few of these today,
which suppliers come first?** It deliberately stays simple and transparent — a
reviewer should be able to recompute any row by hand.

## The formula

```
risk_score = supplier_criticality  ×  vulnerability_weight
```

### Supplier criticality (1–4), from tier
| tier | criticality |
|---|---|
| Critical | 4 |
| High | 3 |
| Medium | 2 |
| Low | 1 |

Tier reflects what the supplier is to the business — a payment processor or
identity provider is Critical; a marketing tool is Low.

### Vulnerability weight (1–4)
```
vuln_weight = 1
            + 2  if linked to known ransomware campaigns
            + 1  if past its CISA remediation due date (overdue)
```

Ransomware linkage is the strongest signal CISA publishes about real-world
impact, so it carries the most weight. Being overdue means the recommended fix
window has already closed.

## Bands

The numeric score (1–16) is bucketed for the report:

| score | band |
|---|---|
| ≥ 9 | Critical |
| 6–8 | High |
| 3–5 | Medium |
| < 3 | Low |

## Worked examples

- **Critical payment supplier, ransomware-linked, overdue CVE:**
  4 × (1 + 2 + 1) = **16 → Critical**.
- **Medium supplier, a 2026 CVE not yet past its due date, no ransomware:**
  2 × (1 + 0 + 0) = **2 → Low**.

## What this is not

It is not CVSS and does not try to be. CVSS scores a vulnerability in the
abstract; this scores *your exposure* to an *actively exploited* vulnerability
through a *specific supplier*. The weights are intentionally coarse and easy to
tune in `pipeline.py` — the point is a defensible ordering, not false precision.

Match confidence is **not** part of the score. It is reported alongside so a
medium-confidence match can be verified independently of how urgent it is.
