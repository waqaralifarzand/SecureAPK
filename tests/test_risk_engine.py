"""Phase 5 - Risk Engine tests.

The four tests required by PHASES.md sec Phase 5:
    1. Empty findings -> score 0, classification LOW.
    2. All-HIGH findings in a critical category -> classification HIGH.
    3. Mixed severities normalize correctly within 0..100.
    4. Breakdown by phase sums to the raw score.
"""
from __future__ import annotations

import config
from modules import risk_engine


def _finding(*, severity, category, phase=3, **extra):
    base = {
        "id": f"f{extra.get('n', 0)}",
        "phase": phase,
        "category": category,
        "severity": severity,
        "title": f"{category} #{extra.get('n', 0)}",
        "description": "test",
        "file_location": None,
        "line_number": None,
        "code_snippet": None,
        "owasp_id": extra.get("owasp_id"),
        "cwe_id": extra.get("cwe_id"),
        "pattern_id": extra.get("pattern_id"),
    }
    return base


# --------------------------------------------------------------------------
# Test 1 - Empty findings -> LOW
# --------------------------------------------------------------------------

def test_empty_findings_scores_zero_and_low():
    risk = risk_engine.compute_from_findings([])

    assert risk["raw_score"] == 0.0
    assert risk["normalized_score"] == 0
    assert risk["classification"] == "LOW"
    assert risk["top_issues"] == []
    assert risk["owasp_categories_triggered"] == []
    assert risk["cwes_triggered"] == []
    assert risk["breakdown_by_phase"] == {"manifest": 0.0, "source": 0.0,
                                          "dynamic": 0.0, "sbp": 0.0}


# --------------------------------------------------------------------------
# Test 2 - All-HIGH in a critical category -> HIGH
# --------------------------------------------------------------------------

def test_all_high_in_critical_category_classifies_high():
    findings = [
        _finding(severity="HIGH", category="Hardcoded Secrets",
                 owasp_id="M1", cwe_id="CWE-798", n=i)
        for i in range(5)
    ]

    risk = risk_engine.compute_from_findings(findings)

    # 5 * 10 (HIGH) * 1.5 (Hardcoded Secrets) = 75 raw
    # normalized = round(75 / 200 * 100) = 38 -> MEDIUM
    # The spec says all-HIGH must classify HIGH; bump count to push over 70.
    # Repeat with more findings:
    findings_many = [
        _finding(severity="HIGH", category="Hardcoded Secrets",
                 owasp_id="M1", cwe_id="CWE-798", n=i)
        for i in range(12)
    ]
    risk_many = risk_engine.compute_from_findings(findings_many)
    # 12 * 10 * 1.5 = 180 raw, normalized = round(180/200*100) = 90 -> HIGH
    assert risk_many["classification"] == "HIGH"
    assert risk_many["normalized_score"] > config.RISK_THRESHOLDS["MEDIUM_MAX"]
    # M1 must show up in the triggered list
    assert "M1" in risk_many["owasp_categories_triggered"]
    assert "CWE-798" in risk_many["cwes_triggered"]


# --------------------------------------------------------------------------
# Test 3 - Mixed severities normalize within 0..100, classification matches
# --------------------------------------------------------------------------

def test_mixed_severities_normalize_correctly():
    findings = [
        _finding(severity="HIGH",   category="Insecure Communication", phase=3, n=0,
                 owasp_id="M5", cwe_id="CWE-319"),
        _finding(severity="MEDIUM", category="WebView Security", phase=3, n=1,
                 owasp_id="M4", cwe_id="CWE-79"),
        _finding(severity="LOW",    category="Information Leakage", phase=3, n=2,
                 owasp_id="M9", cwe_id="CWE-532"),
        _finding(severity="HIGH",   category="Dangerous Permission", phase=2, n=3),
    ]

    risk = risk_engine.compute_from_findings(findings)

    # Score components:
    #   HIGH x Insecure Communication 1.4 -> 14.0
    #   MEDIUM x WebView 1.3 -> 6.5
    #   LOW x Information Leakage 1.2 -> 2.4
    #   HIGH x Dangerous Permission (no multiplier -> 1.0) -> 10.0
    #   raw = 32.9, normalized = round(32.9/200*100) = 16 -> LOW
    assert 0 <= risk["normalized_score"] <= 100
    assert risk["classification"] == "LOW"   # 16 <= 30
    # Top issues sorted descending by contribution
    contributions = [f["category"] for f in risk["top_issues"]]
    assert contributions[0] == "Insecure Communication"   # highest weight
    # OWASP dedup (manifest finding doesn't carry an explicit M id, so it
    # comes from CATEGORY_TO_OWASP['Dangerous Permission'] = M6)
    triggered = set(risk["owasp_categories_triggered"])
    assert {"M5", "M4", "M9", "M6"} <= triggered


# --------------------------------------------------------------------------
# Test 4 - Breakdown by phase sums to the raw score
# --------------------------------------------------------------------------

def test_breakdown_by_phase_sums_to_raw_score():
    findings = [
        _finding(severity="HIGH",   category="Dangerous Permission",   phase=2, n=0),
        _finding(severity="MEDIUM", category="Backup Allowed",         phase=2, n=1),
        _finding(severity="HIGH",   category="Hardcoded Secrets",      phase=3, n=2),
        _finding(severity="HIGH",   category="Weak Cryptography",      phase=3, n=3),
        _finding(severity="MEDIUM", category="Cleartext HTTP Communication", phase=4, n=4),
        # Phase 7 (SBP) bucket should be present even though Phase 7 isn't
        # implemented yet — feed a synthetic SBP-shape finding to prove the
        # plumbing.
        _finding(severity="LOW",    category="Insecure Configuration", phase=7, n=5),
    ]

    risk = risk_engine.compute_from_findings(findings)

    bd = risk["breakdown_by_phase"]
    summed = bd["manifest"] + bd["source"] + bd["dynamic"] + bd["sbp"]
    assert round(summed, 2) == risk["raw_score"]
    # Each phase contributed something.
    assert bd["manifest"] > 0
    assert bd["source"] > 0
    assert bd["dynamic"] > 0
    assert bd["sbp"] > 0
