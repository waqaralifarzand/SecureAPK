"""Tests for modules.db_manager — schema, basic CRUD, and FK cascade."""
from __future__ import annotations

import sqlite3

from modules import db_manager


def test_schema_creates_all_seven_tables(tmp_db):
    expected = {
        "analyses", "findings", "permissions", "exported_components",
        "runtime_events", "sbp_findings", "audit_log",
    }
    with sqlite3.connect(str(tmp_db)) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    names = {r[0] for r in rows}
    assert expected.issubset(names), f"missing tables: {expected - names}"


def test_create_and_fetch_analysis(tmp_db):
    analysis_id = db_manager.create_analysis(
        apk_filename="test.apk",
        apk_path="/tmp/test.apk",
        apk_hash_sha256="a" * 64,
        apk_size_bytes=1234,
        dynamic_enabled=False,
        sbp_enabled=False,
        educational_enabled=True,
        tool_version="SecureAPK 1.0.0",
    )
    assert analysis_id
    row = db_manager.get_analysis(analysis_id)
    assert row is not None
    assert row["apk_filename"] == "test.apk"
    assert row["apk_hash_sha256"] == "a" * 64
    assert row["status"] == "running"
    assert row["educational_enabled"] == 1


def test_delete_analysis_cascades_to_children(tmp_db):
    analysis_id = db_manager.create_analysis(
        apk_filename="x.apk",
        apk_path="/tmp/x.apk",
        apk_hash_sha256="b" * 64,
        apk_size_bytes=10,
        dynamic_enabled=False,
        sbp_enabled=False,
        educational_enabled=False,
        tool_version="SecureAPK 1.0.0",
    )
    db_manager.save_findings(analysis_id, [{
        "phase": 2, "category": "Hardcoded Secrets", "severity": "HIGH",
        "title": "Test", "description": "Test finding",
    }])
    db_manager.add_audit_entry(analysis_id, "analysis_started", details="ok")
    assert len(db_manager.get_findings(analysis_id)) == 1
    assert len(db_manager.get_audit_log(analysis_id)) == 1

    db_manager.delete_analysis(analysis_id)

    assert db_manager.get_analysis(analysis_id) is None
    assert db_manager.get_findings(analysis_id) == []
    assert db_manager.get_audit_log(analysis_id) == []
