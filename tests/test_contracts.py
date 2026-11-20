"""Tests for the data contract: good data passes, each kind of bad data is caught."""
import copy

from supplier_radar import contracts

GOOD_SUPPLIERS = [
    {"supplier_id": "S1", "supplier_name": "Acme", "tier": "Critical",
     "category": "Payments", "data_access": "Financial", "internet_facing": "yes"},
    {"supplier_id": "S2", "supplier_name": "Globex", "tier": "Low",
     "category": "Marketing", "data_access": "None", "internet_facing": "no"},
]
GOOD_PRODUCTS = [
    {"supplier_id": "S1", "vendor": "Microsoft", "product": "Exchange Server"},
    {"supplier_id": "S2", "vendor": "Adobe", "product": "ColdFusion"},
]
GOOD_KEV = [
    {"cveID": "CVE-2021-1", "vendorProject": "Microsoft", "product": "Exchange Server",
     "vulnerabilityName": "x", "dateAdded": "2021-03-03", "knownRansomwareCampaignUse": "Known"},
]


def test_good_data_has_no_violations():
    assert contracts.check_all(GOOD_KEV, GOOD_SUPPLIERS, GOOD_PRODUCTS) == []


def test_invalid_tier_is_caught():
    bad = copy.deepcopy(GOOD_SUPPLIERS)
    bad[0]["tier"] = "Platinum"
    v = contracts.validate_suppliers(bad, GOOD_PRODUCTS)
    assert any(x.rule == "valid_tier" for x in v)


def test_duplicate_supplier_id_is_caught():
    bad = copy.deepcopy(GOOD_SUPPLIERS)
    bad[1]["supplier_id"] = "S1"
    v = contracts.validate_suppliers(bad, GOOD_PRODUCTS)
    assert any(x.rule == "unique_supplier_id" for x in v)


def test_product_referencing_unknown_supplier_is_caught():
    bad_products = GOOD_PRODUCTS + [{"supplier_id": "S99", "vendor": "X", "product": "Y"}]
    v = contracts.validate_suppliers(GOOD_SUPPLIERS, bad_products)
    assert any(x.rule == "known_supplier" for x in v)


def test_missing_column_is_caught():
    stripped = [{k: val for k, val in row.items() if k != "tier"} for row in GOOD_SUPPLIERS]
    v = contracts.validate_suppliers(stripped, GOOD_PRODUCTS)
    assert any(x.rule == "required_columns" for x in v)


def test_bad_ransomware_flag_is_caught():
    bad = copy.deepcopy(GOOD_KEV)
    bad[0]["knownRansomwareCampaignUse"] = "Maybe"
    v = contracts.validate_kev(bad)
    assert any(x.rule == "valid_ransomware_flag" for x in v)
