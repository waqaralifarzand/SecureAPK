"""Phase 9 - End-to-end orchestrator tests.

These exercise `analyzer.run_analysis` with the per-phase analyzer modules
patched to return canned results. No external tools, no real APK content.
Goal: prove the orchestrator wires the phases together, persists state
on the analyses row, and writes the right audit-log entries in the right
order on both the happy and failure paths.
"""
from __future__ import annotations

import hashlib
import os
import zipfile

import pytest

from modules import analyzer, db_manager


def _make_apk(tmp_path):
    apk = tmp_path / "demo.apk"
    with zipfile.ZipFile(apk, "w") as z:
        z.writestr("AndroidManifest.xml", b"stub")
        z.writestr("classes.dex", b"\x00com.demo.app\x00padding text padding\x00")
    return apk


def _seed(apk_path):
    sha = hashlib.sha256(open(apk_path, "rb").read()).hexdigest()
    return db_manager.create_analysis(
        apk_filename="demo.apk", apk_path=str(apk_path),
        apk_hash_sha256=sha, apk_size_bytes=os.path.getsize(apk_path),
        dynamic_enabled=False, sbp_enabled=True, educational_enabled=True,
        tool_version="SecureAPK 1.0.0",
    )


# --------------------------------------------------------------------------
# Happy path: all phases mocked to succeed
# --------------------------------------------------------------------------

def test_orchestrator_happy_path_marks_completed(tmp_db, tmp_path, monkeypatch):
    """Patch every phase analyzer; run; assert status='completed',
    risk + pdf populated, and the expected audit timeline."""
    import config
    monkeypatch.setattr(config, "REPORTS_PATH", tmp_path / "reports")
    monkeypatch.setattr(config, "UPLOADS_PATH", tmp_path / "uploads")
    (tmp_path / "reports").mkdir()
    (tmp_path / "uploads").mkdir()

    apk = _make_apk(tmp_path)
    aid = _seed(apk)

    canned_manifest = {
        "package_name": "com.demo.app", "app_name": "Demo",
        "version_name": "1.0", "version_code": 1,
        "target_sdk": 33, "min_sdk": 21,
        "insecure_flags": {"uses_cleartext_traffic": False, "debuggable": False,
                           "allow_backup": False,
                           "network_security_config": "@xml/nsc"},
        "permissions": [], "exported_components": [],
        "findings": [{
            "id": "m1", "phase": 2, "category": "Dangerous Permission",
            "severity": "HIGH", "title": "Test perm", "description": "t",
            "file_location": None, "line_number": None, "code_snippet": None,
            "owasp_id": "M6", "cwe_id": "CWE-250", "pattern_id": "PERM_TEST",
        }],
        "parser_used": "pyaxmlparser",
    }
    canned_source = {
        "decompiled": True, "decompiler_used": "jadx",
        "files_scanned": 5, "categories_triggered": ["Hardcoded Secrets"],
        "findings": [{
            "id": "s1", "phase": 3, "category": "Hardcoded Secrets",
            "severity": "HIGH", "title": "Hardcoded API Key",
            "description": "x", "file_location": "x.java", "line_number": 7,
            "code_snippet": "k", "owasp_id": "M1", "cwe_id": "CWE-798",
            "pattern_id": "HARDCODED_GOOGLE_API_KEY",
        }],
    }
    monkeypatch.setattr(analyzer.manifest_analyzer, "analyze",
                        lambda _p: canned_manifest)
    monkeypatch.setattr(analyzer.source_analyzer, "analyze",
                        lambda _p: canned_source)
    # SBP is enabled in this test; let the real module run against the
    # canned results so the end-to-end wiring is exercised.

    analyzer.run_analysis(aid, str(apk),
                          analyzer.AnalysisOptions(sbp_enabled=True,
                                                    educational_enabled=True))

    a = db_manager.get_analysis(aid)
    assert a["status"] == "completed"
    assert a["package_name"] == "com.demo.app"
    assert a["risk_classification"] in ("LOW", "MEDIUM", "HIGH")
    assert a["risk_score"] is not None
    assert a["pdf_path"] and os.path.exists(a["pdf_path"])

    actions = [e["action"] for e in db_manager.get_audit_log(aid)]
    for required in ("analysis_started", "hash_verified",
                     "phase_2_completed", "phase_3_completed",
                     "phase_5_completed", "phase_6_completed",
                     "analysis_completed", "phase_7_completed"):
        assert required in actions, f"missing audit action {required!r}"
    # phase_5 must come after the detection phases
    assert actions.index("phase_5_completed") > actions.index("phase_3_completed")
    assert actions.index("phase_5_completed") > actions.index("phase_7_completed")


# --------------------------------------------------------------------------
# Failure path: a phase raises -> orchestrator records failure cleanly
# --------------------------------------------------------------------------

def test_orchestrator_failure_path_marks_failed(tmp_db, tmp_path, monkeypatch):
    apk = _make_apk(tmp_path)
    aid = _seed(apk)

    def boom(_p):
        raise RuntimeError("simulated manifest crash")
    monkeypatch.setattr(analyzer.manifest_analyzer, "analyze", boom)

    with pytest.raises(RuntimeError, match="simulated manifest crash"):
        analyzer.run_analysis(aid, str(apk), analyzer.AnalysisOptions())

    a = db_manager.get_analysis(aid)
    assert a["status"] == "failed"
    assert a["error_message"] and "simulated" in a["error_message"]
    assert a["pdf_path"] is None
    assert a["risk_classification"] is None

    actions = [e["action"] for e in db_manager.get_audit_log(aid)]
    assert "analysis_started" in actions
    assert "analysis_failed" in actions
    # No phase_*_completed entries should have been written.
    assert not any(a.endswith("_completed") and a != "analysis_completed"
                   for a in actions if a.startswith("phase_"))
