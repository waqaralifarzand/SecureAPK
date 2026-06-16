"""Phase 3 — static analysis of decompiled Java source.

Pipeline (ARCHITECTURE.md sec 10):

    1. Primary:  jadx --no-res --output-dir <tmpdir> <apk> + walk *.java
    2. Fallback: extract printable strings from classes*.dex and scan the
                 same regex catalog. Coverage is reduced (no file/line),
                 but never raises.

Pattern source: modules/patterns/vuln_patterns.py (catalog of 34, 9 cats).
Deduplication: same `pattern_id` + same file path -> first match wins.
This prevents result-page flooding from patterns that hit on every class.

Returns a `SourceAnalysisResult` dict per ARCHITECTURE.md sec 6.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Any

import config
from modules.patterns.vuln_patterns import VULN_PATTERNS

log = logging.getLogger(__name__)


_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{6,}")


def analyze(apk_path: str) -> dict[str, Any]:
    """Decompile + scan. Never raises."""
    try:
        if _jadx_available():
            return _analyze_with_jadx(apk_path)
        log.info("Jadx not on PATH; using DEX string extraction fallback for %s", apk_path)
    except Exception as e:  # noqa: BLE001 - fall through to the safety net
        log.warning("Jadx pipeline failed for %s: %s", apk_path, e)

    return _analyze_with_dex_strings(apk_path)


# --------------------------------------------------------------------------
# Primary: Jadx decompile + per-line regex scan
# --------------------------------------------------------------------------

def _jadx_available() -> bool:
    return shutil.which(config.JADX_PATH or "jadx") is not None


def _analyze_with_jadx(apk_path: str) -> dict[str, Any]:
    jadx = config.JADX_PATH or "jadx"
    with tempfile.TemporaryDirectory(prefix="secureapk_jadx_") as tmp:
        out_dir = Path(tmp)
        proc = subprocess.run(
            [jadx, "--no-res", "--output-dir", str(out_dir), apk_path],
            capture_output=True, text=True,
            timeout=config.JADX_TIMEOUT_SECONDS,
        )
        # Jadx exits non-zero on partial decompilation but still produces output.
        # We trust the disk artefacts over the exit code.
        if not any(out_dir.rglob("*.java")):
            raise RuntimeError(f"Jadx produced no .java output (rc={proc.returncode})")

        findings, files_scanned = _scan_java_tree(out_dir)

    categories = sorted({f["category"] for f in findings})
    return {
        "decompiled": True,
        "decompiler_used": "jadx",
        "files_scanned": files_scanned,
        "findings": findings,
        "categories_triggered": categories,
    }


def _scan_java_tree(root: Path) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()   # (pattern_id, file_location) dedup
    files_scanned = 0

    compiled = [(p, re.compile(p["regex"])) for p in VULN_PATTERNS]

    for java in root.rglob("*.java"):
        files_scanned += 1
        try:
            text = java.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        rel = java.relative_to(root).as_posix()

        for pattern, rx in compiled:
            key = (pattern["id"], rel)
            if key in seen_keys:
                continue
            for lineno, line in enumerate(lines, start=1):
                if rx.search(line):
                    findings.append(_make_finding(
                        pattern=pattern,
                        file_location=rel,
                        line_number=lineno,
                        code_snippet=_snippet(lines, lineno),
                    ))
                    seen_keys.add(key)
                    break  # first match per (pattern_id, file) only

    return findings, files_scanned


def _snippet(lines: list[str], lineno: int) -> str:
    lo = max(0, lineno - 2)
    hi = min(len(lines), lineno + 1)
    return "\n".join(lines[lo:hi]).strip()


# --------------------------------------------------------------------------
# Fallback: scan printable strings from classes*.dex inside the APK ZIP
# --------------------------------------------------------------------------

def _analyze_with_dex_strings(apk_path: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()
    files_scanned = 0

    compiled = [(p, re.compile(p["regex"])) for p in VULN_PATTERNS]

    try:
        with zipfile.ZipFile(apk_path) as zf:
            for name in zf.namelist():
                if not name.startswith("classes") or not name.endswith(".dex"):
                    continue
                files_scanned += 1
                try:
                    blob = zf.read(name)
                except (KeyError, zipfile.BadZipFile):
                    continue
                # Concatenate decoded printable runs — gives the regexes plenty
                # of context per match without retaining the raw binary noise.
                strings = []
                for chunk in _PRINTABLE_RE.findall(blob):
                    try:
                        strings.append(chunk.decode("ascii"))
                    except UnicodeDecodeError:
                        continue
                text = "\n".join(strings)

                for pattern, rx in compiled:
                    key = (pattern["id"], name)
                    if key in seen_keys:
                        continue
                    if rx.search(text):
                        findings.append(_make_finding(
                            pattern=pattern,
                            file_location=name,
                            line_number=None,
                            code_snippet=None,
                        ))
                        seen_keys.add(key)
    except (zipfile.BadZipFile, OSError) as e:
        log.error("dex_strings fallback could not open %s: %s", apk_path, e)

    categories = sorted({f["category"] for f in findings})
    return {
        "decompiled": False,
        "decompiler_used": "dex_strings",
        "files_scanned": files_scanned,
        "findings": findings,
        "categories_triggered": categories,
    }


# --------------------------------------------------------------------------
# Finding factory — keeps the shape consistent with ARCHITECTURE.md sec 6
# --------------------------------------------------------------------------

def _make_finding(*, pattern: dict, file_location: str | None,
                  line_number: int | None, code_snippet: str | None) -> dict[str, Any]:
    return {
        "id": uuid.uuid4().hex,
        "phase": 3,
        "category": pattern["category"],
        "severity": pattern["severity"],
        "title": pattern["title"],
        "description": pattern["description"],
        "file_location": file_location,
        "line_number": line_number,
        "code_snippet": code_snippet,
        "owasp_id": pattern.get("owasp_id"),
        "cwe_id": pattern.get("cwe_id"),
        "pattern_id": pattern["id"],
    }
