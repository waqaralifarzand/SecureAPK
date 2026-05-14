"""Forensic helpers — SHA-256 + audit logging + chain-of-custody helpers.

Phase 6 expands this module with chain-of-custody helpers consumed by
`report_generator.py` for the PDF appendix. The forensic guarantee:
every analysis state change in `audit_log` is reproduced in the PDF
in chronological order, alongside the APK's SHA-256 hash — together
they establish that the report describes a specific, unmodified
artefact analysed at a specific time.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from modules import db_manager


def compute_sha256(filepath: str) -> str:
    """Return the SHA-256 hex digest of a file, streamed in chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def audit(action: str, analysis_id: str, actor: str = "system", details: Any = None) -> None:
    """Append an audit log entry. `details` is JSON-encoded when not a string."""
    if details is not None and not isinstance(details, str):
        details = json.dumps(details, default=str)
    db_manager.add_audit_entry(analysis_id, action, actor, details)


# --------------------------------------------------------------------------
# Phase 6: chain-of-custody helpers consumed by report_generator
# --------------------------------------------------------------------------

def get_chain_of_custody(analysis_id: str) -> list[dict[str, Any]]:
    """Return audit_log entries for the analysis in chronological order.

    The DB helper already ORDERs by (timestamp, id); we re-expose it here
    so report_generator imports only from `forensic` and the chain-of-
    custody contract lives in one module.
    """
    return db_manager.get_audit_log(analysis_id)


def format_audit_for_pdf(entries: list[dict[str, Any]]) -> list[list[str]]:
    """Flatten audit_log rows into [timestamp, action, details] string rows
    ready for a ReportLab Table. JSON `details` blobs are pretty-printed
    so the PDF stays human-readable."""
    rows: list[list[str]] = []
    for e in entries:
        ts = str(e.get("timestamp") or "")
        action = str(e.get("action") or "")
        details_raw = e.get("details")
        if details_raw is None or details_raw == "":
            details = ""
        else:
            try:
                obj = json.loads(details_raw) if isinstance(details_raw, str) else details_raw
                if isinstance(obj, dict):
                    details = ", ".join(f"{k}={obj[k]}" for k in obj)
                else:
                    details = str(obj)
            except (ValueError, TypeError):
                details = str(details_raw)
        rows.append([ts, action, details])
    return rows
