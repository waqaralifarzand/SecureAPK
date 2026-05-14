"""Phase 8 - Educational Mode lookup layer.

Thin module: takes a finding id, joins to the source-code pattern catalog
in `modules/patterns/vuln_patterns.py`, and returns the pattern's
`remediation` dict (vulnerable_snippet / fixed_snippet / explanation).

Per ARCHITECTURE.md sec 11.3, only Phase 3 source-code findings have
educational content - manifest, dynamic, and SBP findings return None
because their pattern_ids do not appear in VULN_PATTERNS. The Phase 3
integrity test in test_source_analyzer guarantees every entry in
VULN_PATTERNS carries a complete remediation dict, so a found
pattern_id is always sufficient.
"""
from __future__ import annotations

from typing import Any

from modules import db_manager
from modules.patterns.vuln_patterns import VULN_PATTERNS


# Build the lookup once at import time. O(1) at request time afterwards.
_REMEDIATION_BY_PATTERN_ID: dict[str, dict[str, str]] = {
    p["id"]: p["remediation"] for p in VULN_PATTERNS
}


def get_remediation_for_pattern(pattern_id: str | None) -> dict[str, str] | None:
    """Return the remediation dict for a pattern id, or None if no match.
    Used internally by `get_remediation_for_finding` and by the PDF
    generator when iterating findings."""
    if not pattern_id:
        return None
    return _REMEDIATION_BY_PATTERN_ID.get(pattern_id)


def get_remediation_for_finding(finding_id: str) -> dict[str, str] | None:
    """Return the educational remediation dict for a finding, or None.

    Returns None when:
        * the finding id does not exist
        * the finding has no pattern_id (manifest / dynamic / SBP)
        * the pattern_id is not a key in VULN_PATTERNS (defensive)
    """
    finding = _get_finding(finding_id)
    if finding is None:
        return None
    return get_remediation_for_pattern(finding.get("pattern_id"))


def _get_finding(finding_id: str) -> dict[str, Any] | None:
    """Single-row helper. db_manager only exposes a per-analysis list, so
    we scan the all-analyses join - cheap because findings are small and
    the lookup is keyed on the indexed `id` column."""
    return db_manager.get_finding(finding_id)
