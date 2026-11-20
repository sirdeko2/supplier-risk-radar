"""Tests for matching, confidence and scoring - the logic a reviewer will question."""
from supplier_radar.pipeline import run

AS_OF = "2026-11-20"


def _one(suppliers, products, kev, **kw):
    return run(suppliers, products, kev, "test", as_of=AS_OF, **kw)


def _supplier(sid, tier, access="None", facing="no"):
    return {"supplier_id": sid, "supplier_name": sid, "tier": tier,
            "category": "c", "data_access": access, "internet_facing": facing}


def _vuln(cve, vendor, product, ransomware="Unknown", due="2020-01-01"):
    return {"cveID": cve, "vendorProject": vendor, "product": product, "vulnerabilityName": cve,
            "dateAdded": "2020-01-01", "dueDate": due, "knownRansomwareCampaignUse": ransomware,
            "cwes": [], "shortDescription": ""}


def test_exact_match_is_high_confidence():
    r = _one([_supplier("S1", "Low")],
             [{"supplier_id": "S1", "vendor": "Microsoft", "product": "Exchange Server"}],
             [_vuln("CVE-1", "Microsoft", "Exchange Server")])
    assert len(r.findings) == 1
    assert r.findings[0]["match_confidence"] == "High"


def test_substring_match_is_medium_confidence():
    # Supplier runs a component named inside a broader KEV product string.
    r = _one([_supplier("S1", "Low")],
             [{"supplier_id": "S1", "vendor": "Citrix", "product": "NetScaler Gateway"}],
             [_vuln("CVE-1", "Citrix", "NetScaler ADC and NetScaler Gateway")])
    assert len(r.findings) == 1
    assert r.findings[0]["match_confidence"] == "Medium"


def test_no_match_leaves_supplier_clean():
    r = _one([_supplier("S1", "Critical")],
             [{"supplier_id": "S1", "vendor": "Okta", "product": "Workforce Identity"}],
             [_vuln("CVE-1", "Microsoft", "Exchange Server")])
    assert r.findings == []
    assert r.suppliers_exposed == 0


def test_vendor_must_match_even_if_product_matches():
    # Same product word, different vendor -> not a match (no false positive across vendors).
    r = _one([_supplier("S1", "Critical")],
             [{"supplier_id": "S1", "vendor": "VendorA", "product": "Gateway"}],
             [_vuln("CVE-1", "VendorB", "Gateway")])
    assert r.findings == []


def test_ransomware_and_overdue_raise_the_score():
    crit_rw_overdue = _one([_supplier("S1", "Critical")],
                           [{"supplier_id": "S1", "vendor": "V", "product": "P"}],
                           [_vuln("CVE-1", "V", "P", ransomware="Known", due="2020-01-01")])
    # criticality 4 * weight (1 + 2 ransomware + 1 overdue = 4) = 16
    assert crit_rw_overdue.findings[0]["risk_score"] == 16
    assert crit_rw_overdue.findings[0]["risk_band"] == "Critical"


def test_future_due_date_is_not_overdue():
    r = _one([_supplier("S1", "Medium")],
             [{"supplier_id": "S1", "vendor": "V", "product": "P"}],
             [_vuln("CVE-1", "V", "P", ransomware="Unknown", due="2099-01-01")])
    f = r.findings[0]
    assert f["overdue"] is False
    # criticality 2 * weight 1 = 2 -> Low
    assert f["risk_score"] == 2
    assert f["risk_band"] == "Low"


def test_findings_are_sorted_worst_first():
    suppliers = [_supplier("LOW", "Low"), _supplier("CRIT", "Critical")]
    products = [{"supplier_id": "LOW", "vendor": "V", "product": "P"},
                {"supplier_id": "CRIT", "vendor": "V", "product": "P"}]
    r = _one(suppliers, products, [_vuln("CVE-1", "V", "P", ransomware="Known")])
    scores = [f["risk_score"] for f in r.findings]
    assert scores == sorted(scores, reverse=True)


def test_every_finding_carries_source_and_as_of():
    r = _one([_supplier("S1", "Low")],
             [{"supplier_id": "S1", "vendor": "V", "product": "P"}],
             [_vuln("CVE-1", "V", "P")])
    f = r.findings[0]
    assert f["source"] == "CISA KEV"
    assert f["as_of"] == AS_OF
