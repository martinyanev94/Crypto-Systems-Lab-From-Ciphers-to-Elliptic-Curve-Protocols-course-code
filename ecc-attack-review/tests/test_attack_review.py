from src.attack_review import checklist, review_signatures


def test_repeated_r_is_critical():
    findings = review_signatures([(12, 5), (12, 9)])
    assert len(findings) == 1
    assert findings[0].area == "nonce"
    assert findings[0].priority == "critical"
    assert findings[0].evidence == "repeated r"


def test_distinct_r_values_have_no_nonce_signal():
    assert review_signatures([(12, 5), (13, 9)]) == []


def test_checklist_contains_curve_and_migration_boundaries():
    areas = {finding.area for finding in checklist()}
    assert "curve" in areas
    assert "lifecycle" in areas
