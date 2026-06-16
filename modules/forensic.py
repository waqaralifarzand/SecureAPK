"""Forensic helpers — hashing, audit logging, chain-of-custody, and
environment capture for court-admissible reporting.

Phase 6 established the core: SHA-256 at upload, audit_log in the PDF
appendix. Phase 11 expands with multi-hash (SHA-256 + SHA-1 + MD5),
software environment capture, ISO 8601 timezone-aware timestamps, and
formatted chain-of-custody output for the court-admissible report.
"""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

import config
from modules import db_manager


def compute_sha256(filepath: str) -> str:
    """Return the SHA-256 hex digest of a file, streamed in chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_multi_hash(filepath: str) -> dict[str, str]:
    """Read a file once and return SHA-256, SHA-1, and MD5 hex digests."""
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1(usedforsecurity=False)
    md5 = hashlib.md5(usedforsecurity=False)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }


def audit(action: str, analysis_id: str, actor: str = "system", details: Any = None) -> None:
    """Append an audit log entry. `details` is JSON-encoded when not a string."""
    if details is not None and not isinstance(details, str):
        details = json.dumps(details, default=str)
    db_manager.add_audit_entry(analysis_id, action, actor, details)


# --------------------------------------------------------------------------
# Phase 6: chain-of-custody helpers consumed by report_generator
# --------------------------------------------------------------------------

def get_chain_of_custody(analysis_id: str) -> list[dict[str, Any]]:
    """Return audit_log entries for the analysis in chronological order."""
    return db_manager.get_audit_log(analysis_id)


# --------------------------------------------------------------------------
# Phase 11: court-admissible report helpers
# --------------------------------------------------------------------------

def get_software_environment() -> dict[str, str]:
    """Capture the host software versions for the report cover."""
    env: dict[str, str] = {
        "os": platform.platform(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "secureapk": config.TOOL_VERSION,
    }
    jadx = config.JADX_PATH or "jadx"
    if shutil.which(jadx):
        try:
            out = subprocess.run(
                [jadx, "--version"], capture_output=True, text=True, timeout=10,
            )
            env["jadx"] = out.stdout.strip().split("\n")[0] if out.returncode == 0 else "installed (version unknown)"
        except (OSError, subprocess.TimeoutExpired):
            env["jadx"] = "installed (version unknown)"
    else:
        env["jadx"] = "not installed"

    adb = config.ADB_PATH or "adb"
    if shutil.which(adb):
        try:
            out = subprocess.run(
                [adb, "version"], capture_output=True, text=True, timeout=10,
            )
            first_line = out.stdout.strip().split("\n")[0] if out.returncode == 0 else ""
            env["adb"] = first_line or "installed (version unknown)"
        except (OSError, subprocess.TimeoutExpired):
            env["adb"] = "installed (version unknown)"
    else:
        env["adb"] = "not installed"

    return env


def format_iso8601_with_tz(dt_str: str | None) -> str:
    """Convert a stored timestamp string into ISO 8601 with explicit TZ offset.

    The DB stores UTC ISO strings from ``datetime.now(timezone.utc).isoformat()``.
    We parse, convert to the configured timezone, and format as
    ``2026-05-31T14:41:50+05:00``.
    """
    if not dt_str:
        return ""
    try:
        tz = ZoneInfo(config.REPORT_TIMEZONE)
    except (KeyError, Exception):
        tz = timezone.utc

    try:
        dt = datetime.fromisoformat(dt_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local = dt.astimezone(tz)
        return local.strftime("%Y-%m-%dT%H:%M:%S") + _tz_offset_str(local)
    except (ValueError, TypeError):
        return str(dt_str)


def now_iso8601_with_tz() -> str:
    """Return the current timestamp as ISO 8601 with the configured TZ offset."""
    try:
        tz = ZoneInfo(config.REPORT_TIMEZONE)
    except (KeyError, Exception):
        tz = timezone.utc
    return datetime.now(tz).strftime("%Y-%m-%dT%H:%M:%S") + _tz_offset_str(datetime.now(tz))


def _tz_offset_str(dt: datetime) -> str:
    """Format the UTC offset of a tz-aware datetime as ``+HH:MM``."""
    off = dt.utcoffset()
    if off is None:
        return "+00:00"
    total = int(off.total_seconds())
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    return f"{sign}{total // 3600:02d}:{(total % 3600) // 60:02d}"
