-- Example Athena queries against the warehouse. These are the same questions
-- the local report answers, now in standard SQL against S3 data.

-- 1. The worst exposures first - who to call today.
SELECT supplier_name, cve_id, vuln_name, risk_band, risk_score, match_confidence
FROM supplier_risk.fact_exposure
ORDER BY risk_score DESC, supplier_name
LIMIT 25;

-- 2. Exposure count and peak risk per supplier.
SELECT supplier_name, tier,
       count(*)        AS exposures,
       max(risk_score) AS top_risk,
       sum(CASE WHEN ransomware THEN 1 ELSE 0 END) AS ransomware_linked
FROM supplier_risk.fact_exposure
GROUP BY supplier_name, tier
ORDER BY top_risk DESC, exposures DESC;

-- 3. How many suppliers are exposed at all, vs the total.
SELECT
    (SELECT count(*) FROM supplier_risk.dim_supplier)                       AS suppliers_total,
    (SELECT count(DISTINCT supplier_id) FROM supplier_risk.fact_exposure)   AS suppliers_exposed;

-- 4. Medium-confidence matches to review by hand (fuzzy product matches).
SELECT supplier_name, vendor, supplier_product, kev_product, cve_id
FROM supplier_risk.fact_exposure
WHERE match_confidence = 'Medium'
ORDER BY risk_score DESC;

-- 5. Ransomware-linked exposures on internet-facing suppliers - the sharpest subset.
SELECT supplier_name, cve_id, vuln_name, risk_score
FROM supplier_risk.fact_exposure
WHERE ransomware AND internet_facing
ORDER BY risk_score DESC;
