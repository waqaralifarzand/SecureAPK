"""Phase 6 - Forensic helpers tests.

Three required tests from PHASES.md sec Phase 6:
    1. compute_sha256 matches sha256sum output for the same file
    2. audit() writes a row to audit_log
    3. Audit entries come back in chronological order
"""
from __future__ import annotations

import hashlib
import time

import pytest

from modules import db_manager, forensic


def _create_analysis() -> str:
    return db_manager.create_analysis(
        apk_filename="demo.apk",
        apk_path="uploads/demo.apk",
        apk_hash_sha256="0" * 64,
        apk_size_bytes=42,
        dynamic_enabled=False,
        sbp_enabled=False,
        educational_enabled=False,
        tool_version="SecureAPK 1.0.0",
    )


def test_compute_sha256_matches_hashlib_sha256(tmp_path):
    payload = b"SecureAPK forensic chain-of-custody test payload " * 100
    target = tmp_path / "evidence.bin"
    target.write_bytes(payload)

    expected = hashlib.sha256(payload).hexdigest()
    actual = forensic.compute_sha256(str(target))

    assert actual == expected
    assert len(actual) == 64


def test_audit_writes_a_row_to_audit_log(tmp_db):
    analysis_id = _create_analysis()

    forensic.audit("test_action", analysis_id, details={"k": "v"})

    rows = db_manager.get_audit_log(analysis_id)
    test_rows = [r for r in rows if r["action"] == "test_action"]
    assert len(test_rows) == 1
    row = test_rows[0]
    assert row["actor"] == "system"
    assert "k" in (row["details"] or "")
    assert row["timestamp"]   # populated by DEFAULT CURRENT_TIMESTAMP


def test_audit_entries_chronological_order(tmp_db):
    analysis_id = _create_analysis()

    forensic.audit("first", analysis_id, details="1")
    # Sub-second resolution on CURRENT_TIMESTAMP; sleep just enough to make
    # the timestamps monotonic so ordering can be asserted strictly.
    time.sleep(1.05)
    forensic.audit("second", analysis_id, details="2")
    time.sleep(1.05)
    forensic.audit("third", analysis_id, details="3")

    rows = db_manager.get_audit_log(analysis_id)
    custom = [r for r in rows if r["action"] in ("first", "second", "third")]
    assert [r["action"] for r in custom] == ["first", "second", "third"]
    # And timestamps are non-decreasing
    timestamps = [r["timestamp"] for r in custom]
    assert timestamps == sorted(timestamps)
