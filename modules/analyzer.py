"""Orchestrator. Phase 1 = placeholder. Real phases wired in subsequently.

This is the ONLY module that knows the phase sequence. app.py spawns
run_analysis() in a daemon thread and never calls phase modules directly.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, asdict

from modules import (
    db_manager, dynamic_analyzer, forensic, manifest_analyzer, source_analyzer,
)


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

        # Phase 2 — Manifest static analysis.
        db_manager.set_current_phase(analysis_id, 2)
        manifest = manifest_analyzer.analyze(apk_path)
        db_manager.save_manifest_metadata(analysis_id, manifest)
        db_manager.save_permissions(analysis_id, manifest["permissions"])
        db_manager.save_exported_components(analysis_id, manifest["exported_components"])
        db_manager.save_findings(analysis_id, manifest["findings"])
        db_manager.set_parser_used(analysis_id, manifest["parser_used"])
        forensic.audit(
            "phase_2_completed",
            analysis_id,
            details={
                "findings": len(manifest["findings"]),
                "parser_used": manifest["parser_used"],
                "dangerous_permissions": sum(1 for p in manifest["permissions"] if p["is_dangerous"]),
            },
        )
        db_manager.set_progress(analysis_id, 25)

        # Phase 3 — Source code static analysis.
        db_manager.set_current_phase(analysis_id, 3)
        source = source_analyzer.analyze(apk_path)
        db_manager.save_findings(analysis_id, source["findings"])
        db_manager.add_audit_entry(
            analysis_id, "source_decompiler", details=source["decompiler_used"],
        )
        forensic.audit(
            "phase_3_completed",
            analysis_id,
            details={
                "findings": len(source["findings"]),
                "decompiler_used": source["decompiler_used"],
                "files_scanned": source["files_scanned"],
                "categories": source["categories_triggered"],
            },
        )
        db_manager.set_progress(analysis_id, 50)

        # Phase 4 — Dynamic runtime analysis (optional).
        if options.dynamic_enabled:
            db_manager.set_current_phase(analysis_id, 4)
            dynamic = dynamic_analyzer.analyze(apk_path, manifest.get("package_name"))
            db_manager.save_runtime_events(analysis_id, dynamic["events"])
            db_manager.save_findings(analysis_id, dynamic["findings"])
            db_manager.add_audit_entry(
                analysis_id, "dynamic_status", details=dynamic["status"],
            )
            forensic.audit(
                "phase_4_completed",
                analysis_id,
                details={
                    "status": dynamic["status"],
                    "events": len(dynamic["events"]),
                    "findings": len(dynamic["findings"]),
                    "logcat_seconds": dynamic["logcat_duration_seconds"],
                },
            )
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

        db_manager.mark_completed(analysis_id)
        forensic.audit("analysis_completed", analysis_id)

    except Exception as e:  # never silently swallow
        log.exception("analysis %s failed", analysis_id)
        db_manager.mark_failed(analysis_id, str(e))
        forensic.audit("analysis_failed", analysis_id, details={"error": str(e)})
        raise
