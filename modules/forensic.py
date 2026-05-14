"""Forensic helpers: SHA-256 hashing and audit logging. Expanded in Phase 6."""
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
