"""Phase 3 - Source Code Analyzer tests.

The five tests required by PHASES.md sec Phase 3:
    1. Successful Jadx decompilation produces findings with file/line.
    2. Detection of a hardcoded Google API key.
    3. Detection of MessageDigest.getInstance("MD5").
    4. DEX string fallback when Jadx is unavailable.
    5. Per-pattern-per-file deduplication.

Plus one Phase 8 contract test:
    6. Every VULN_PATTERNS entry has a complete `remediation` dict.
"""
from __future__ import annotations

import re
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from modules import source_analyzer
from modules.patterns.vuln_patterns import CATEGORIES, VULN_PATTERNS


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _stub_jadx(monkeypatch, java_files: dict[str, str]):
    """Make `jadx` appear installed and produce the given .java tree."""
    monkeypatch.setattr(source_analyzer.shutil, "which", lambda _n: "/usr/bin/jadx")

    def fake_run(cmd, **kwargs):
        # The third-to-last arg is `--output-dir`, second-to-last is the dir.
        out_dir = Path(cmd[cmd.index("--output-dir") + 1])
        for rel, body in java_files.items():
            target = out_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(source_analyzer.subprocess, "run", fake_run)


# --------------------------------------------------------------------------
# Test 1 - Successful Jadx decompilation
# --------------------------------------------------------------------------

def test_jadx_decompilation_produces_findings(monkeypatch, tmp_path):
    _stub_jadx(monkeypatch, {
        "com/example/app/Login.java": (
            "package com.example.app;\n"
            "public class Login {\n"
            "    String token = \"AIzaSyB0aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456\";\n"
            "    public void run() {\n"
            "        String api = \"http://api.example.com\";\n"
            "    }\n"
            "}\n"
        ),
    })
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"unused - jadx is stubbed")

    result = source_analyzer.analyze(str(apk))

    assert result["decompiler_used"] == "jadx"
    assert result["decompiled"] is True
    assert result["files_scanned"] == 1
    assert len(result["findings"]) >= 2
    # File/line info must be populated under the Jadx path.
    for f in result["findings"]:
        assert f["file_location"] == "com/example/app/Login.java"
        assert isinstance(f["line_number"], int) and f["line_number"] > 0
        assert f["phase"] == 3


# --------------------------------------------------------------------------
# Test 2 - Hardcoded Google API key
# --------------------------------------------------------------------------

def test_detects_hardcoded_google_api_key(monkeypatch, tmp_path):
    _stub_jadx(monkeypatch, {
        "Net.java": 'String k = "AIzaSyA-bC1deF2GHi3jKLm4nopq5RstUvWxYz67890";',
    })
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"unused")
    result = source_analyzer.analyze(str(apk))

    ids = {f["pattern_id"] for f in result["findings"]}
    assert "HARDCODED_GOOGLE_API_KEY" in ids
    finding = next(f for f in result["findings"] if f["pattern_id"] == "HARDCODED_GOOGLE_API_KEY")
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Hardcoded Secrets"
    assert finding["owasp_id"] == "M1"
    assert finding["cwe_id"] == "CWE-798"


# --------------------------------------------------------------------------
# Test 3 - MD5 weak crypto
# --------------------------------------------------------------------------

def test_detects_md5_weak_crypto(monkeypatch, tmp_path):
    _stub_jadx(monkeypatch, {
        "Hash.java": 'MessageDigest md = MessageDigest.getInstance("MD5");',
    })
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"unused")
    result = source_analyzer.analyze(str(apk))

    ids = {f["pattern_id"] for f in result["findings"]}
    assert "WEAK_HASH_MD5" in ids
    md5 = next(f for f in result["findings"] if f["pattern_id"] == "WEAK_HASH_MD5")
    assert md5["category"] == "Weak Cryptography"
    assert md5["severity"] == "HIGH"


# --------------------------------------------------------------------------
# Test 4 - DEX string fallback when Jadx unavailable
# --------------------------------------------------------------------------

def test_falls_back_to_dex_strings_when_jadx_missing(monkeypatch, tmp_path):
    # Pretend jadx is not on PATH.
    monkeypatch.setattr(source_analyzer.shutil, "which", lambda _n: None)

    apk = tmp_path / "fb.apk"
    # Synthesise a "classes.dex" with strings the regex catalog will recognise.
    dex_blob = (
        b"\x00\x00\x00\x00 placeholder dex header noise \x00\x00\x00\x00"
        b"AIzaSyA0123456789abcdef0123456789ABCDEFGHI\x00\x00"
        b"MessageDigest.getInstance(\"MD5\")\x00\x00"
        b"plenty of padding so printable runs are long enough \x00\x00"
    )
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("classes.dex", dex_blob)

    result = source_analyzer.analyze(str(apk))

    assert result["decompiler_used"] == "dex_strings"
    assert result["decompiled"] is False
    ids = {f["pattern_id"] for f in result["findings"]}
    assert "HARDCODED_GOOGLE_API_KEY" in ids
    assert "WEAK_HASH_MD5" in ids
    # No file/line under the fallback path.
    for f in result["findings"]:
        assert f["file_location"] == "classes.dex"
        assert f["line_number"] is None


# --------------------------------------------------------------------------
# Test 5 - Per-pattern-per-file deduplication
# --------------------------------------------------------------------------

def test_pattern_dedup_within_a_file(monkeypatch, tmp_path):
    # Same MD5 pattern appears six times in one file; one match per (pattern, file).
    body = "\n".join([
        'MessageDigest.getInstance("MD5");',
        'MessageDigest.getInstance("MD5");',
        'MessageDigest.getInstance("MD5");',
        'MessageDigest.getInstance("MD5");',
        'MessageDigest.getInstance("MD5");',
        'MessageDigest.getInstance("MD5");',
    ])
    _stub_jadx(monkeypatch, {"a/B.java": body, "c/D.java": body})
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"unused")

    result = source_analyzer.analyze(str(apk))
    md5_findings = [f for f in result["findings"] if f["pattern_id"] == "WEAK_HASH_MD5"]
    # Two files * one finding each = exactly two MD5 findings.
    assert len(md5_findings) == 2
    locations = {f["file_location"] for f in md5_findings}
    assert locations == {"a/B.java", "c/D.java"}


# --------------------------------------------------------------------------
# Test 6 - Phase 8 contract: every pattern has a complete remediation dict.
# --------------------------------------------------------------------------

def test_every_pattern_has_complete_remediation():
    required = ("vulnerable_snippet", "fixed_snippet", "explanation")
    for p in VULN_PATTERNS:
        r = p.get("remediation")
        assert isinstance(r, dict), f"{p['id']}: remediation missing"
        for k in required:
            assert r.get(k), f"{p['id']}: remediation.{k} empty/missing"


# --------------------------------------------------------------------------
# Bonus integrity assertions — cheap and prevent silent drift of chapter
# claims. Not strictly required by PHASES.md.
# --------------------------------------------------------------------------

def test_pattern_catalog_size_and_categories():
    assert len(VULN_PATTERNS) >= 30
    assert {p["category"] for p in VULN_PATTERNS} == set(CATEGORIES)
    assert len(CATEGORIES) == 9


def test_every_pattern_compiles_as_regex():
    for p in VULN_PATTERNS:
        try:
            re.compile(p["regex"])
        except re.error as e:
            pytest.fail(f"{p['id']}: invalid regex {p['regex']!r}: {e}")
