"""Phase 7 - SBP Banking Compliance tests.

The three required tests from PHASES.md sec Phase 7:
    1. Banking-app heuristic identifies a JazzCash APK
    2. TLS rule trips on cleartext-traffic manifest
    3. SBP findings excluded when sbp_enabled=False

Plus the catalog count sanity test.
"""
from __future__ import annotations

import hashlib
import os
import zipfile

from modules import analyzer, db_manager, sbp_compliance
from modules.patterns.sbp_rules import SBP_RULES


# --------------------------------------------------------------------------
# Test 1 - JazzCash heuristic
# --------------------------------------------------------------------------

def test_banking_heuristic_identifies_jazzcash():
    manifest = {
        "package_name": "com.techlogix.mobilinkcustomer",
        "app_name": "JazzCash",
        "permissions": [],
        "insecure_flags": {},
    }
    flag, reason = sbp_compliance.is_banking_app(manifest)
    assert flag is True
    assert "jazzcash" in reason.lower()

    # Negative: a non-banking app must not trip.
    manifest_neg = {
        "package_name": "com.spotify.music",
        "app_name": "Spotify",
        "permissions": [],
        "insecure_flags": {},
    }
    flag2, _ = sbp_compliance.is_banking_app(manifest_neg)
    assert flag2 is False


# --------------------------------------------------------------------------
# Test 2 - TLS rule trips on cleartext
# --------------------------------------------------------------------------

def test_tls_rule_trips_on_cleartext_manifest():
    manifest = {
        "package_name": "com.test.app",
        "app_name": "Test",
        "permissions": [],
        "exported_components": [],
        "insecure_flags": {
            "uses_cleartext_traffic": True,
            "debuggable": False,
            "allow_backup": False,
            "network_security_config": None,
        },
        "findings": [],
    }
    source = {"decompiler_used": "jadx", "findings": []}
    result = sbp_compliance.analyze("dummy.apk", manifest, source, None)

    tls_rule = next(r for r in result["rules"] if r["rule_id"] == "SBP-CSF-3.2.1")
    assert tls_rule["compliance_status"] == "NON_COMPLIANT"
    assert "cleartext" in tls_rule["evidence"].lower()
    assert tls_rule["severity"] == "HIGH"
    # And it shows up as a phase-7 finding ready for the risk engine.
    assert any(f["pattern_id"] == "SBP-CSF-3.2.1" for f in result["findings"])


# --------------------------------------------------------------------------
# Test 3 - SBP excluded when sbp_enabled=False
# --------------------------------------------------------------------------

def test_sbp_findings_excluded_when_disabled(tmp_path, tmp_db, monkeypatch):
    import app as appmod

    monkeypatch.setattr(appmod.config, "REPORTS_PATH", tmp_path / "reports")
    monkeypatch.setattr(appmod.config, "UPLOADS_PATH", tmp_path / "uploads")
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
    (tmp_path / "uploads").mkdir(parents=True, exist_ok=True)

    # Synthesise a minimal APK ZIP that the analyzer can chew on.
    apk = tmp_path / "uploads" / "x.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", b"stub")
        z.writestr("classes.dex", b"\x00com.test.app\x00padding text\x00")

    sha = hashlib.sha256(open(apk, "rb").read()).hexdigest()
    aid = db_manager.create_analysis(
        apk_filename="x.apk", apk_path=str(apk), apk_hash_sha256=sha,
        apk_size_bytes=os.path.getsize(apk),
        dynamic_enabled=False, sbp_enabled=False, educational_enabled=False,
        tool_version="test",
    )
    db_manager.set_apk_path(aid, str(apk))

    analyzer.run_analysis(aid, str(apk),
                          analyzer.AnalysisOptions(sbp_enabled=False))

    rows = db_manager.get_sbp_findings(aid)
    assert rows == []   # Phase 7 should not have run

    client = appmod.app.test_client()
    html = client.get(f"/analysis/{aid}").get_data(as_text=True)
    assert 'data-tab="sbp"' not in html
    assert 'data-tab-panel="sbp"' not in html


# --------------------------------------------------------------------------
# Catalog count sanity
# --------------------------------------------------------------------------

def test_sbp_rule_pack_has_at_least_ten_rules():
    assert len(SBP_RULES) >= 10
    ids = [r["id"] for r in SBP_RULES]
    assert len(ids) == len(set(ids))
