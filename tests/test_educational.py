"""Phase 8 - Educational Mode tests.

The two required tests from PHASES.md sec Phase 8:
    1. Integrity: every VULN_PATTERNS entry carries a complete remediation
       dict (vulnerable_snippet, fixed_snippet, explanation). Phase 3
       already has this; we re-assert here so Phase 8's contract is
       captured in its own test file too.
    2. Functional: educational.get_remediation_for_finding returns the
       right dict for a finding inserted into the DB.
"""
from __future__ import annotations

from modules import db_manager, educational
from modules.patterns.vuln_patterns import VULN_PATTERNS


# --------------------------------------------------------------------------
# Test 1 - integrity (Phase 8 depends on Phase 3 having shipped every
#                    remediation dict; reaffirm here)
# --------------------------------------------------------------------------

def test_every_pattern_has_complete_remediation_dict():
    required = ("vulnerable_snippet", "fixed_snippet", "explanation")
    for p in VULN_PATTERNS:
        rem = p.get("remediation")
        assert isinstance(rem, dict), f"{p['id']}: remediation missing"
        for k in required:
            assert rem.get(k), f"{p['id']}: remediation.{k} empty/missing"


# --------------------------------------------------------------------------
# Test 2 - functional: known finding -> correct remediation dict
# --------------------------------------------------------------------------

def test_get_remediation_for_finding_returns_correct_dict(tmp_db):
    aid = db_manager.create_analysis(
        apk_filename="x.apk", apk_path="uploads/x.apk",
        apk_hash_sha256="0" * 64, apk_size_bytes=42,
        dynamic_enabled=False, sbp_enabled=False, educational_enabled=True,
        tool_version="test",
    )
    # Pick a real pattern from the catalog so the round-trip is genuine.
    pattern = next(p for p in VULN_PATTERNS if p["id"] == "HARDCODED_GOOGLE_API_KEY")
    db_manager.save_findings(aid, [{
        "id": "f-known", "phase": 3, "category": pattern["category"],
        "severity": pattern["severity"], "title": pattern["title"],
        "description": pattern["description"],
        "file_location": "com/x/Net.java", "line_number": 1,
        "code_snippet": "String k = \"AIza...\";",
        "owasp_id": pattern["owasp_id"], "cwe_id": pattern["cwe_id"],
        "pattern_id": pattern["id"],
    }])

    rem = educational.get_remediation_for_finding("f-known")

    assert rem is not None
    assert rem["vulnerable_snippet"] == pattern["remediation"]["vulnerable_snippet"]
    assert rem["fixed_snippet"]      == pattern["remediation"]["fixed_snippet"]
    assert rem["explanation"]        == pattern["remediation"]["explanation"]

    # Negative paths: unknown finding id; finding without a pattern_id;
    # finding with a pattern_id absent from the catalog.
    assert educational.get_remediation_for_finding("does-not-exist") is None

    db_manager.save_findings(aid, [{
        "id": "f-noptr", "phase": 2, "category": "Dangerous Permission",
        "severity": "HIGH", "title": "READ_SMS", "description": "",
        "file_location": None, "line_number": None, "code_snippet": None,
        "owasp_id": None, "cwe_id": None, "pattern_id": None,
    }])
    assert educational.get_remediation_for_finding("f-noptr") is None

    db_manager.save_findings(aid, [{
        "id": "f-bogus", "phase": 3, "category": "x", "severity": "LOW",
        "title": "x", "description": "x",
        "file_location": None, "line_number": None, "code_snippet": None,
        "owasp_id": None, "cwe_id": None, "pattern_id": "PATTERN_NEVER_REGISTERED",
    }])
    assert educational.get_remediation_for_finding("f-bogus") is None
