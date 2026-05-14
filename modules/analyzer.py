"""Orchestrator. Phase 1 = placeholder. Real phases wired in subsequently.

This is the ONLY module that knows the phase sequence. app.py spawns
run_analysis() in a daemon thread and never calls phase modules directly.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, asdict

from modules import db_manager, forensic


log = logging.getLogger(__name__)


@dataclass
class AnalysisOptions:
    dynamic_enabled: bool = False
    sbp_enabled: bool = False
    educational_enabled: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def run_analysis(analysis_id: str, apk_path: str, options: AnalysisOptions) -> None:
    """Phase 1 placeholder. Logs the phase sequence and marks status='completed'.

    The real per-phase implementations are added in Phases 2-6.
    """
    try:
        forensic.audit("analysis_started", analysis_id, details=options.to_dict())

        analysis = db_manager.get_analysis(analysis_id)
        if analysis:
            forensic.audit(
                "hash_verified",
                analysis_id,
                details={"sha256": analysis["apk_hash_sha256"]},
            )

        # Placeholder for Phase 2 (Manifest).
        db_manager.set_current_phase(analysis_id, 2)
        log.info("Phase 2 (manifest) not implemented yet for analysis %s", analysis_id)
        db_manager.set_progress(analysis_id, 25)

        # Placeholder for Phase 3 (Source).
        db_manager.set_current_phase(analysis_id, 3)
        log.info("Phase 3 (source) not implemented yet for analysis %s", analysis_id)
        db_manager.set_progress(analysis_id, 50)

        # Placeholder for Phase 4 (Dynamic, optional).
        if options.dynamic_enabled:
            db_manager.set_current_phase(analysis_id, 4)
            log.info("Phase 4 (dynamic) not implemented yet for analysis %s", analysis_id)
        db_manager.set_progress(analysis_id, 70)

        # Placeholder for Phase 7 (SBP, optional).
        if options.sbp_enabled:
            db_manager.set_current_phase(analysis_id, 7)
            log.info("Phase 7 (SBP) not implemented yet for analysis %s", analysis_id)
        db_manager.set_progress(analysis_id, 80)

        # Placeholder for Phase 5 (Risk).
        db_manager.set_current_phase(analysis_id, 5)
        log.info("Phase 5 (risk) not implemented yet for analysis %s", analysis_id)
        db_manager.set_progress(analysis_id, 90)

        # Placeholder for Phase 6 (PDF).
        db_manager.set_current_phase(analysis_id, 6)
        log.info("Phase 6 (PDF) not implemented yet for analysis %s", analysis_id)

        # Simulate a small amount of work so polling can observe 'running' state.
        time.sleep(2)

        db_manager.mark_completed(analysis_id)
        forensic.audit("analysis_completed", analysis_id)

    except Exception as e:  # never silently swallow
        log.exception("analysis %s failed", analysis_id)
        db_manager.mark_failed(analysis_id, str(e))
        forensic.audit("analysis_failed", analysis_id, details={"error": str(e)})
        raise
