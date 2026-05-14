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
from werkzeug.utils import secure_filename

import config
from modules import analyzer, db_manager, forensic, risk_engine


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_SIZE_MB * 1024 * 1024
app.config["SECRET_KEY"] = config.SECRET_KEY


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
    # Recompute the RiskAssessment for the view so the breakdown / top-issues
    # tables have access to the structured data (the analyses row only stores
    # score + classification).
    risk = risk_engine.compute_from_findings(findings) if analysis["status"] == "completed" else None
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
    analyses = db_manager.list_analyses()
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
    # Placeholder — wired up in Phase 8.
    return jsonify({"error": "educational mode not yet implemented"}), 404


@app.route("/health")
def health():
    return jsonify({
        "python_ok": True,
        "jadx_ok": _binary_present(config.JADX_PATH or "jadx"),
        "adb_ok": _binary_present(config.ADB_PATH or "adb"),
        "emulator_ok": _emulator_running(),
    })


def _binary_present(name: str) -> bool:
    return shutil.which(name) is not None


def _emulator_running() -> bool:
    adb = config.ADB_PATH or "adb"
    if shutil.which(adb) is None:
        return False
    try:
        out = subprocess.run(
            [adb, "devices"], capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    if out.returncode != 0:
        return False
    # Parse "List of devices attached\n<id>\tdevice\n"
    for line in out.stdout.splitlines()[1:]:
        if line.strip().endswith("device"):
            return True
    return False


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
