"""Flask routes only. Thin HTTP layer — no analysis logic here."""
from __future__ import annotations

import logging
import shutil
import subprocess
import threading
from pathlib import Path

from flask import (
    Flask, abort, jsonify, redirect, render_template, request, send_file, url_for,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

import config
from modules import analyzer, db_manager, educational, forensic, risk_engine


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_SIZE_MB * 1024 * 1024
app.config["SECRET_KEY"] = config.SECRET_KEY
csrf = CSRFProtect(app)


@app.context_processor
def inject_brand_globals():
    """Expose presentation-only globals to every template (Phase 10 redesign).

    The brand footer year and the upload-size hint are config values, never
    hardcoded in the markup (CLAUDE.md §5). Injected here so the templates can
    stay logic-free.
    """
    return {
        "footer_year": config.FOOTER_YEAR,
        "max_upload_mb": config.MAX_UPLOAD_SIZE_MB,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("apk_file")
    if not file or not file.filename:
        return render_template("index.html", error="No file selected."), 400

    filename = secure_filename(file.filename)
    if not filename.lower().endswith(".apk"):
        return render_template("index.html", error="Only .apk files are accepted."), 400

    options = analyzer.AnalysisOptions(
        dynamic_enabled=bool(request.form.get("dynamic_enabled")),
        sbp_enabled=bool(request.form.get("sbp_enabled")),
        educational_enabled=bool(request.form.get("educational_enabled")),
    )

    # Phase 11: analyst name — optional, max 100 chars, strip control chars.
    raw_analyst = (request.form.get("analyst_name") or "").strip()[:100]
    analyst_name = "".join(c for c in raw_analyst if c.isprintable()) or None

    config.UPLOADS_PATH.mkdir(parents=True, exist_ok=True)

    # Save under a temporary name first, hash, then rename to <analysis_id>.apk.
    tmp_path = config.UPLOADS_PATH / f"_incoming_{filename}"
    file.save(str(tmp_path))
    size = tmp_path.stat().st_size
    sha256 = forensic.compute_sha256(str(tmp_path))

    analysis_id = db_manager.create_analysis(
        apk_filename=filename,
        apk_path="",  # filled in below
        apk_hash_sha256=sha256,
        apk_size_bytes=size,
        dynamic_enabled=options.dynamic_enabled,
        sbp_enabled=options.sbp_enabled,
        educational_enabled=options.educational_enabled,
        tool_version=f"{config.TOOL_NAME} {config.TOOL_VERSION}",
    )

    final_path = config.UPLOADS_PATH / f"{analysis_id}.apk"
    tmp_path.rename(final_path)

    db_manager.set_apk_path(analysis_id, str(final_path))
    if analyst_name:
        db_manager.set_analyst_name(analysis_id, analyst_name)

    threading.Thread(
        target=analyzer.run_analysis,
        args=(analysis_id, str(final_path), options),
        daemon=True,
    ).start()

    return redirect(url_for("view_analysis", analysis_id=analysis_id))


@app.route("/analysis/<analysis_id>")
def view_analysis(analysis_id: str):
    analysis = db_manager.get_analysis(analysis_id)
    if not analysis:
        abort(404)
    findings = db_manager.get_findings(analysis_id)
    permissions = db_manager.get_permissions(analysis_id)
    exported_components = db_manager.get_exported_components(analysis_id)
    audit_entries = db_manager.get_audit_log(analysis_id)
    parser_used = next(
        (e["details"] for e in audit_entries if e["action"] == "manifest_parser"),
        None,
    )
    manifest_findings = [f for f in findings if f["phase"] == 2]
    source_findings = [f for f in findings if f["phase"] == 3]
    dynamic_findings = [f for f in findings if f["phase"] == 4]
    runtime_events = db_manager.get_runtime_events(analysis_id)
    decompiler_used = next(
        (e["details"] for e in audit_entries if e["action"] == "source_decompiler"),
        None,
    )
    dynamic_status = next(
        (e["details"] for e in audit_entries if e["action"] == "dynamic_status"),
        None,
    )
    # Phase 7: SBP rule results (only populated when sbp_enabled=True).
    sbp_rules = db_manager.get_sbp_findings(analysis_id) if analysis.get("sbp_enabled") else []
    sbp_counts = {"COMPLIANT": 0, "NON_COMPLIANT": 0,
                  "NOT_APPLICABLE": 0, "MANUAL_REVIEW": 0}
    for r in sbp_rules:
        sbp_counts[r["compliance_status"]] = sbp_counts.get(r["compliance_status"], 0) + 1

    # Recompute the RiskAssessment for the view so the breakdown / top-issues
    # tables have access to the structured data. Mirror the orchestrator-side
    # `risk_engine.compute()` by appending SBP non-compliant findings into the
    # in-memory list before scoring.
    if analysis["status"] == "completed":
        risk_findings = list(findings) + risk_engine.sbp_findings_as_findings(analysis_id)
        risk = risk_engine.compute_from_findings(risk_findings)
    else:
        risk = None
    # Group source findings by category for the Source Code tab.
    source_by_category: dict[str, list] = {}
    for f in source_findings:
        source_by_category.setdefault(f["category"], []).append(f)

    return render_template(
        "result.html",
        analysis=analysis,
        findings=findings,
        manifest_findings=manifest_findings,
        source_findings=source_findings,
        source_by_category=source_by_category,
        decompiler_used=decompiler_used,
        dynamic_findings=dynamic_findings,
        runtime_events=runtime_events,
        dynamic_status=dynamic_status,
        permissions=permissions,
        exported_components=exported_components,
        parser_used=parser_used,
        risk=risk,
        sbp_rules=sbp_rules,
        sbp_counts=sbp_counts,
    )


@app.route("/analysis/<analysis_id>/report.pdf")
def download_report(analysis_id: str):
    analysis = db_manager.get_analysis(analysis_id)
    if not analysis or not analysis.get("pdf_path"):
        abort(404)
    pdf_path = analysis["pdf_path"]
    if not Path(pdf_path).exists():
        abort(404)
    pkg = (analysis.get("package_name") or "report").replace("/", "_")
    download_name = f"secureapk_{pkg}_{analysis_id[:8]}.pdf"
    return send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=download_name,
    )


@app.route("/dashboard")
def dashboard():
    analyses = db_manager.list_analyses_with_counts()
    return render_template("dashboard.html", analyses=analyses)


@app.route("/analysis/<analysis_id>/delete", methods=["POST"])
def delete_analysis(analysis_id: str):
    analysis = db_manager.get_analysis(analysis_id)
    if analysis:
        # Remove APK from disk; preserve only DB cascade for child rows.
        apk_path = analysis.get("apk_path")
        if apk_path and Path(apk_path).exists():
            try:
                Path(apk_path).unlink()
            except OSError:
                pass
        db_manager.delete_analysis(analysis_id)
    return redirect(url_for("dashboard"))


@app.route("/api/analysis/<analysis_id>/status")
def api_status(analysis_id: str):
    analysis = db_manager.get_analysis(analysis_id)
    if not analysis:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "status": analysis["status"],
        "current_phase": analysis["current_phase"],
        "progress_pct": analysis["progress_pct"],
    })


@app.route("/api/finding/<finding_id>/educational")
def api_finding_educational(finding_id: str):
    remediation = educational.get_remediation_for_finding(finding_id)
    if remediation is None:
        return jsonify({"error": "No educational content for this finding"}), 404
    return jsonify({
        "vulnerable_snippet": remediation["vulnerable_snippet"],
        "fixed_snippet":      remediation["fixed_snippet"],
        "explanation":        remediation["explanation"],
    })


@app.route("/health")
def health():
    return jsonify({
        "python_ok": True,
        "jadx_ok": _binary_present(config.JADX_PATH or "jadx"),
        "adb_ok": _binary_present(config.ADB_PATH or "adb"),
        "emulator_ok": _emulator_running(),
    })


@app.route("/api/health/adb")
@csrf.exempt
def api_health_adb():
    adb = config.ADB_PATH or "adb"
    adb_installed = _binary_present(adb)
    emulator_serial = None
    if adb_installed:
        emulator_serial = _emulator_serial(adb)
    return jsonify({
        "adb_installed": adb_installed,
        "emulator_running": emulator_serial is not None,
        "emulator_serial": emulator_serial,
    })


def _binary_present(name: str) -> bool:
    return shutil.which(name) is not None


def _emulator_serial(adb: str) -> str | None:
    """Return the first online device serial, or None."""
    if shutil.which(adb) is None:
        return None
    try:
        out = subprocess.run(
            [adb, "devices"], capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if out.returncode != 0:
        return None
    for line in out.stdout.splitlines()[1:]:
        if line.strip().endswith("device"):
            return line.strip().split()[0]
    return None


def _emulator_running() -> bool:
    adb = config.ADB_PATH or "adb"
    return _emulator_serial(adb) is not None


@app.errorhandler(413)
def too_large(_e):
    return render_template(
        "index.html",
        error=f"File too large. Max is {config.MAX_UPLOAD_SIZE_MB} MB.",
    ), 413


if __name__ == "__main__":
    db_manager.init_db()
    config.UPLOADS_PATH.mkdir(parents=True, exist_ok=True)
    config.REPORTS_PATH.mkdir(parents=True, exist_ok=True)
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
