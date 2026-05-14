"""Phase 5 - weighted risk scoring + OWASP MTW10 / CWE aggregation.

Pure post-processing: reads findings rows for an `analysis_id` from the DB
via `db_manager.get_findings`, applies the scoring contract from
`config.py` (SEVERITY_WEIGHTS x CATEGORY_MULTIPLIERS), normalizes to
0..100, and classifies LOW / MEDIUM / HIGH per `RISK_THRESHOLDS`.

No external tools. No subprocess. Never reaches across to another phase
module. The orchestrator runs this phase AFTER the detection phases
(Phase 2 manifest, 3 source, 4 dynamic, eventually 7 SBP).
"""
from __future__ import annotations

from typing import Any

import config
from modules import db_manager
from modules.patterns.owasp_cwe_map import (
    CATEGORY_TO_CWE, CATEGORY_TO_OWASP, OWASP_MTW10_2024,
)


# Phase number -> breakdown-key. Findings carry an integer `phase` column;
# the RiskAssessment.breakdown_by_phase dict surfaces human-readable keys.
_PHASE_BUCKET = {2: "manifest", 3: "source", 4: "dynamic", 7: "sbp"}


def compute(analysis_id: str) -> dict[str, Any]:
    """Return a `RiskAssessment` dict matching ARCHITECTURE.md sec 6."""
    findings = db_manager.get_findings(analysis_id)
    return compute_from_findings(findings)


def compute_from_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Same as compute() but takes findings directly. Used by tests."""
    raw_score = 0.0
    breakdown = {"manifest": 0.0, "source": 0.0, "dynamic": 0.0, "sbp": 0.0}
    scored: list[tuple[float, dict[str, Any]]] = []

    for f in findings:
        contrib = _score_contribution(f)
        raw_score += contrib
        bucket = _PHASE_BUCKET.get(f.get("phase"))
        if bucket:
            breakdown[bucket] += contrib
        scored.append((contrib, f))

    normalized = min(100, round(raw_score / config.SCORE_NORMALIZATION_DIVISOR * 100))
    classification = _classify(normalized)

    # Top 5 by individual contribution, descending.
    scored.sort(key=lambda pair: pair[0], reverse=True)
    top_issues = [f for _, f in scored[:5]]

    # OWASP / CWE aggregation. Prefer the value persisted on the finding row
    # but fall back to the category map for rows that didn't carry an explicit
    # owasp_id / cwe_id (e.g. Phase 4 dynamic findings).
    owasp_set: set[str] = set()
    cwe_set: set[str] = set()
    for f in findings:
        owasp = f.get("owasp_id") or CATEGORY_TO_OWASP.get(f.get("category", ""))
        cwe = f.get("cwe_id") or CATEGORY_TO_CWE.get(f.get("category", ""))
        if owasp:
            owasp_set.add(owasp)
        if cwe:
            cwe_set.add(cwe)

    return {
        "raw_score": round(raw_score, 2),
        "normalized_score": int(normalized),
        "classification": classification,
        "breakdown_by_phase": {k: round(v, 2) for k, v in breakdown.items()},
        "top_issues": top_issues,
        "owasp_categories_triggered": sorted(
            owasp_set, key=lambda m: int(m.lstrip("M")) if m.startswith("M") and m[1:].isdigit() else 99,
        ),
        "owasp_names": {m: OWASP_MTW10_2024[m] for m in owasp_set if m in OWASP_MTW10_2024},
        "cwes_triggered": sorted(cwe_set),
        "total_findings": len(findings),
    }


def _score_contribution(finding: dict[str, Any]) -> float:
    severity = (finding.get("severity") or "").upper()
    weight = config.SEVERITY_WEIGHTS.get(severity, 0)
    if weight == 0:
        return 0.0
    multiplier = config.CATEGORY_MULTIPLIERS.get(finding.get("category", ""), 1.0)
    return float(weight) * float(multiplier)


def _classify(normalized_score: int) -> str:
    if normalized_score <= config.RISK_THRESHOLDS["LOW_MAX"]:
        return "LOW"
    if normalized_score <= config.RISK_THRESHOLDS["MEDIUM_MAX"]:
        return "MEDIUM"
    return "HIGH"
