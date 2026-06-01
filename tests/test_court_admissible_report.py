"""Phase 11 — Court-Admissible Forensic Report tests.

Four tests verifying the expanded PDF meets ISO/IEC 27037:2012 requirements:
    1. SHA-256 visible on the cover (first ~30% of PDF bytes)
    2. Chain of Custody appendix present with matching audit-log count
    3. All timestamps use ISO 8601 with explicit timezone offset
    4. Page footer contains ``Page X of Y`` pattern

All tests read PDF bytes directly (pageCompression=0 from Phase 6).
"""
from __future__ import annotations

import os
import re
import zipfile

import config
from modules import analyzer, db_manager, forensic, report_generator


def _create_analysis(tmp_path, monkeypatch):
    """Seed a completed analysis with findings for PDF generation."""
    monkeypatch.setattr(config, "REPORTS_PATH", tmp_path / "reports")
    monkeypatch.setattr(config, "UPLOADS_PATH", tmp_path / "uploads")
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
    (tmp_path / "uploads").mkdir(parents=True, exist_ok=True)

    apk = tmp_path / "uploads" / "test.apk"
    with zipfile.ZipFile(str(apk), "w") as z:
        z.writestr("AndroidManifest.xml", b"stub")
        z.writestr("classes.dex", b"\x00com.test.app\x00password=hunter2\x00")

    sha = forensic.compute_sha256(str(apk))
    aid = db_manager.create_analysis(
        apk_filename="test.apk",
        apk_path=str(apk),
        apk_hash_sha256=sha,
        apk_size_bytes=os.path.getsize(str(apk)),
        dynamic_enabled=False,
        sbp_enabled=False,
        educational_enabled=False,
        tool_version="SecureAPK 1.0.0",
    )
    db_manager.set_apk_path(aid, str(apk))
    db_manager.set_analyst_name(aid, "Test Analyst")
    analyzer.run_analysis(
        aid, str(apk),
        analyzer.AnalysisOptions(dynamic_enabled=False, sbp_enabled=False,
                                 educational_enabled=False),
    )
    return aid, sha


def test_sha256_visible_on_cover(tmp_path, tmp_db, monkeypatch):
    """SHA-256 hash must appear as readable text in the first ~30% of the PDF."""
    aid, sha = _create_analysis(tmp_path, monkeypatch)
    pdf_path = report_generator.generate(aid)
    blob = open(pdf_path, "rb").read()
    cover_region = blob[: len(blob) * 30 // 100]
    assert sha.encode() in cover_region, (
        f"SHA-256 {sha[:16]}... not found in first 30% of PDF bytes"
    )


def test_chain_of_custody_appendix_present(tmp_path, tmp_db, monkeypatch):
    """Chain of Custody appendix must appear and contain all audit-log entries."""
    aid, _ = _create_analysis(tmp_path, monkeypatch)
    pdf_path = report_generator.generate(aid)
    blob = open(pdf_path, "rb").read()

    assert b"Chain of Custody" in blob, "Chain of Custody heading missing from PDF"

    audit_entries = db_manager.get_audit_log(aid)
    assert len(audit_entries) > 0, "No audit entries in DB"

    # Each audit entry produces a timestamp line in the appendix region.
    # Count ISO 8601 timestamp patterns in the appendix portion of the PDF
    # (after "Chain of Custody").
    appendix_start = blob.find(b"Chain of Custody")
    appendix_region = blob[appendix_start:]
    ts_pattern = re.compile(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{2}:\d{2}")
    ts_matches = ts_pattern.findall(appendix_region)
    assert len(ts_matches) >= len(audit_entries), (
        f"Expected >= {len(audit_entries)} timestamps in appendix, found {len(ts_matches)}"
    )


def test_iso8601_timestamps_with_timezone(tmp_path, tmp_db, monkeypatch):
    """All timestamps in the PDF must use ISO 8601 with explicit TZ offset."""
    aid, _ = _create_analysis(tmp_path, monkeypatch)
    pdf_path = report_generator.generate(aid)
    blob = open(pdf_path, "rb").read()

    # Find all timestamp-shaped strings — should all have TZ offsets.
    # We look for the pattern YYYY-MM-DDTHH:MM:SS and check it's followed by +/-HH:MM.
    naive_pattern = re.compile(
        rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?![+\-])"
    )
    tz_pattern = re.compile(
        rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{2}:\d{2}"
    )
    tz_matches = tz_pattern.findall(blob)
    assert len(tz_matches) >= 2, (
        f"Expected >= 2 TZ-aware timestamps, found {len(tz_matches)}"
    )

    # Filter out naive timestamps that aren't part of a TZ-aware one.
    # Replace all TZ-aware patterns with a placeholder, then look for leftovers.
    scrubbed = tz_pattern.sub(b"__TZ_OK__", blob)
    naive_leftovers = naive_pattern.findall(scrubbed)
    assert len(naive_leftovers) == 0, (
        f"Found {len(naive_leftovers)} naive timestamps without TZ offset"
    )


def test_page_footer_format(tmp_path, tmp_db, monkeypatch):
    """Every page must have a ``Page X of Y`` footer."""
    aid, _ = _create_analysis(tmp_path, monkeypatch)
    pdf_path = report_generator.generate(aid)
    blob = open(pdf_path, "rb").read()

    page_pattern = re.compile(rb"Page \d+ of \d+")
    matches = page_pattern.findall(blob)
    assert len(matches) >= 2, (
        f"Expected Page X of Y on multiple pages, found {len(matches)} occurrences"
    )
