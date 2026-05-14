"""Phase 6 - ReportLab Platypus PDF report generator.

Produces the forensic-grade security report that ships SecureAPK's first
MobSF differentiator: every report embeds the APK's SHA-256 hash on the
cover page and a chronological audit-log appendix for chain-of-custody.

Layout (per ARCHITECTURE.md sec 11.1):
    1. Cover - tool, title, app name/package, APK hash, timestamps,
                analyst, tool version
    2. Risk Summary - banner, score, phase breakdown, top 5 issues
    3. Manifest - metadata, insecure flags, permissions, exported, findings
    4. Source Code - findings grouped by category
    5. Dynamic (only if enabled) - status, runtime events, findings
    6. OWASP MTW10 + CWE - triggered categories with full names
    7. Audit Log Appendix - chain-of-custody, chronological

Determinism: findings are sorted (severity DESC, category ASC, title ASC)
before rendering so repeat generations produce byte-identical body
content (the only timestamp embedded in the body is the analysis'
own started_at / completed_at, which are stable for a completed run).
"""
from __future__ import annotations

import logging
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

import config
from modules import db_manager, forensic, risk_engine
from modules.patterns.owasp_cwe_map import OWASP_MTW10_2024

log = logging.getLogger(__name__)


# CLAUDE.md sec 5 severity colours, lifted into ReportLab colour objects.
_SEV_COLOR = {
    "HIGH":   colors.HexColor("#ff4d4f"),
    "MEDIUM": colors.HexColor("#faad14"),
    "LOW":    colors.HexColor("#52c41a"),
}
_ACCENT = colors.HexColor("#00d4ff")
_BORDER = colors.HexColor("#2d3447")
_TEXT_PRIMARY = colors.HexColor("#0d1117")    # dark ink for print legibility
_TEXT_SECONDARY = colors.HexColor("#57606a")
_BG_HEADER = colors.HexColor("#0a0e1a")
_BG_HEADER_TEXT = colors.HexColor("#e6edf3")


_SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------

def generate(analysis_id: str) -> str:
    """Build the PDF and return the saved path. Persists path on the
    `analyses` row is the orchestrator's job, not ours."""
    analysis = db_manager.get_analysis(analysis_id)
    if not analysis:
        raise ValueError(f"analysis_id not found: {analysis_id}")

    findings = _sort_findings(db_manager.get_findings(analysis_id))
    permissions = db_manager.get_permissions(analysis_id)
    exported = db_manager.get_exported_components(analysis_id)
    runtime_events = db_manager.get_runtime_events(analysis_id)
    audit_entries = forensic.get_chain_of_custody(analysis_id)
    sbp_rules = (db_manager.get_sbp_findings(analysis_id)
                 if analysis.get("sbp_enabled") else [])
    # Include SBP non-compliant rows in scoring so the PDF risk page
    # matches the orchestrator-side risk write.
    risk_findings = list(findings) + risk_engine._sbp_findings_as_findings(analysis_id)
    risk = risk_engine.compute_from_findings(risk_findings)

    config.REPORTS_PATH.mkdir(parents=True, exist_ok=True)
    out_path = config.REPORTS_PATH / f"{analysis_id}.pdf"

    # pageCompression=0 keeps content streams uncompressed. Two payoffs:
    #   1) forensic transparency - the SHA-256 hash appears as plain text in
    #      the PDF bytes, so any examiner can `grep` it without unpacking.
    #   2) deterministic output - two regenerations of the same analysis
    #      produce byte-identical content streams (no zlib non-determinism).
    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title=f"SecureAPK Report - {analysis_id}",
        author=config.TOOL_NAME,
        pageCompression=0,
        # invariant=True freezes the /CreationDate, /ModDate and /ID fields
        # ReportLab would otherwise stamp from the system clock. Combined
        # with pageCompression=0 this means two regenerations of a
        # completed analysis produce byte-identical PDF output - the
        # forensic-reproducibility guarantee.
        invariant=True,
    )

    styles = _build_styles()
    story: list = []

    _build_cover(story, styles, analysis)
    _build_risk_summary(story, styles, risk)
    _build_manifest_section(story, styles, analysis, permissions, exported,
                            [f for f in findings if f["phase"] == 2])
    _build_source_section(story, styles, [f for f in findings if f["phase"] == 3])
    if analysis.get("dynamic_enabled"):
        _build_dynamic_section(story, styles, runtime_events,
                               [f for f in findings if f["phase"] == 4])
    if analysis.get("sbp_enabled"):
        _build_sbp_section(story, styles, sbp_rules)
    _build_owasp_cwe_section(story, styles, risk)
    _build_audit_appendix(story, styles, audit_entries)

    doc.build(story)
    return str(out_path)


# --------------------------------------------------------------------------
# Determinism helpers
# --------------------------------------------------------------------------

def _sort_findings(findings):
    return sorted(
        findings,
        key=lambda f: (
            f.get("phase") or 0,
            _SEVERITY_RANK.get((f.get("severity") or "").upper(), 9),
            f.get("category") or "",
            f.get("title") or "",
        ),
    )


def _build_styles() -> dict:
    base = getSampleStyleSheet()
    ui = base["BodyText"].fontName
    return {
        "Title":       ParagraphStyle("Title", parent=base["Title"],
                                       fontSize=28, leading=32, textColor=_ACCENT,
                                       fontName="Helvetica-Bold"),
        "Subtitle":    ParagraphStyle("Subtitle", parent=base["Heading2"],
                                       fontSize=14, textColor=_TEXT_SECONDARY,
                                       fontName=ui),
        "H1":          ParagraphStyle("H1", parent=base["Heading1"], fontSize=18,
                                       leading=22, spaceBefore=12, spaceAfter=8,
                                       textColor=_TEXT_PRIMARY),
        "H2":          ParagraphStyle("H2", parent=base["Heading2"], fontSize=14,
                                       leading=18, spaceBefore=10, spaceAfter=6,
                                       textColor=_TEXT_PRIMARY),
        "Body":        ParagraphStyle("Body", parent=base["BodyText"], fontSize=10,
                                       leading=14, textColor=_TEXT_PRIMARY),
        "Muted":       ParagraphStyle("Muted", parent=base["BodyText"], fontSize=9,
                                       textColor=_TEXT_SECONDARY),
        "Mono":        ParagraphStyle("Mono", parent=base["Code"], fontSize=8,
                                       leading=11, fontName="Courier",
                                       textColor=_TEXT_PRIMARY),
        "MonoLarge":   ParagraphStyle("MonoLarge", parent=base["Code"], fontSize=10,
                                       leading=13, fontName="Courier-Bold",
                                       textColor=_TEXT_PRIMARY),
    }


# --------------------------------------------------------------------------
# Sections
# --------------------------------------------------------------------------

def _build_cover(story, styles, analysis):
    story.append(Paragraph("SecureAPK", styles["Title"]))
    story.append(Paragraph("Security Analysis Report", styles["Subtitle"]))
    story.append(Spacer(1, 18))

    rows = [
        ["Application name", _str(analysis.get("app_name"))],
        ["Package name",     _str(analysis.get("package_name"))],
        ["Version",          f"{_str(analysis.get('version_name'))} "
                             f"({_str(analysis.get('version_code'))})"],
        ["Original filename", _str(analysis.get("apk_filename"))],
        ["File size (bytes)", _str(analysis.get("apk_size_bytes"))],
        ["", ""],
        ["APK SHA-256",       _str(analysis.get("apk_hash_sha256"))],
        ["", ""],
        ["Analysis started",   _str(analysis.get("started_at"))],
        ["Analysis completed", _str(analysis.get("completed_at"))],
        ["", ""],
        ["Analyst",          "Anonymous Analyst"],
        ["Tool version",     f"{config.TOOL_NAME} {config.TOOL_VERSION}"],
    ]
    table = Table(rows, colWidths=[5 * cm, 11 * cm])
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("FONTNAME", (1, 6), (1, 6), "Courier-Bold"),   # hash row
        ("TEXTCOLOR", (1, 6), (1, 6), _ACCENT),
        ("TEXTCOLOR", (0, 0), (0, -1), _TEXT_SECONDARY),
        ("VALIGN",   (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)
    story.append(Spacer(1, 24))
    story.append(Paragraph(
        "<i>Forensic integrity: re-hash the analysed APK with "
        "<font face='Courier'>sha256sum</font> and compare against the value above. "
        "An exact match proves this report describes the same artefact that was uploaded.</i>",
        styles["Muted"],
    ))
    story.append(PageBreak())


def _build_risk_summary(story, styles, risk):
    story.append(Paragraph("Risk Summary", styles["H1"]))

    classification = risk["classification"]
    score = risk["normalized_score"]
    banner = Table(
        [[f"{classification}   {score}/100"]], colWidths=[16 * cm],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _SEV_COLOR[classification]),
        ("TEXTCOLOR", (0, 0), (-1, -1), _BG_HEADER),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 18),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(banner)
    story.append(Spacer(1, 14))
    story.append(Paragraph(
        f"Raw score: <b>{risk['raw_score']}</b> &nbsp;|&nbsp; "
        f"Total findings: <b>{risk['total_findings']}</b>", styles["Body"],
    ))

    story.append(Paragraph("Score breakdown by phase", styles["H2"]))
    bd = risk["breakdown_by_phase"]
    bd_rows = [["Phase", "Raw contribution"]]
    for label, key in (("Manifest", "manifest"), ("Source", "source"),
                       ("Dynamic", "dynamic"), ("SBP", "sbp")):
        bd_rows.append([label, f"{bd[key]:.2f}"])
    story.append(_styled_table(bd_rows, [4 * cm, 4 * cm]))

    story.append(Paragraph("Top issues", styles["H2"]))
    if risk["top_issues"]:
        rows = [["Severity", "Category", "Title"]]
        for f in risk["top_issues"]:
            rows.append([f.get("severity", ""), f.get("category", ""),
                         _trim(f.get("title", ""), 80)])
        t = _styled_table(rows, [2.5 * cm, 4.5 * cm, 9 * cm], severity_col=0)
        story.append(t)
    else:
        story.append(Paragraph("No findings recorded.", styles["Muted"]))

    story.append(PageBreak())


def _build_manifest_section(story, styles, analysis, permissions, exported, manifest_findings):
    story.append(Paragraph("Manifest Analysis", styles["H1"]))

    meta = [
        ["Target SDK", _str(analysis.get("target_sdk"))],
        ["Min SDK", _str(analysis.get("min_sdk"))],
        ["Version", _str(analysis.get("version_name"))],
    ]
    story.append(_styled_table(meta, [4 * cm, 8 * cm]))

    dangerous = [p for p in permissions if p.get("is_dangerous")]
    story.append(Paragraph(f"Dangerous permissions ({len(dangerous)})", styles["H2"]))
    if dangerous:
        rows = [["Permission", "Severity"]]
        for p in dangerous:
            rows.append([_str(p.get("permission_name")), _str(p.get("severity"))])
        story.append(_styled_table(rows, [11 * cm, 3 * cm], severity_col=1))
    else:
        story.append(Paragraph("None.", styles["Muted"]))

    story.append(Paragraph(f"Exported components ({len(exported)})", styles["H2"]))
    if exported:
        rows = [["Type", "Name", "Protected", "Dangerous"]]
        for c in exported:
            rows.append([
                _str(c.get("component_type")),
                _trim(_str(c.get("component_name")), 60),
                "yes" if c.get("is_protected") else "no",
                "YES" if c.get("is_dangerous") else "no",
            ])
        story.append(_styled_table(rows, [2.5 * cm, 9 * cm, 2 * cm, 2.5 * cm]))
    else:
        story.append(Paragraph("No exported components recorded.", styles["Muted"]))

    story.append(Paragraph(f"Manifest findings ({len(manifest_findings)})", styles["H2"]))
    for f in manifest_findings:
        _append_finding(story, styles, f)

    story.append(PageBreak())


def _build_source_section(story, styles, source_findings):
    story.append(Paragraph("Source Code Analysis", styles["H1"]))
    if not source_findings:
        story.append(Paragraph("No source code findings.", styles["Muted"]))
        story.append(PageBreak())
        return

    by_cat: dict[str, list] = {}
    for f in source_findings:
        by_cat.setdefault(f.get("category", "Uncategorised"), []).append(f)
    for category in sorted(by_cat):
        story.append(Paragraph(f"{category} ({len(by_cat[category])})", styles["H2"]))
        for f in by_cat[category]:
            _append_finding(story, styles, f)
    story.append(PageBreak())


def _build_dynamic_section(story, styles, runtime_events, dynamic_findings):
    story.append(Paragraph("Dynamic Analysis", styles["H1"]))
    story.append(Paragraph(
        f"Runtime events captured: <b>{len(runtime_events)}</b> &nbsp;|&nbsp; "
        f"Dynamic findings: <b>{len(dynamic_findings)}</b>", styles["Body"],
    ))

    if runtime_events:
        story.append(Paragraph("Runtime events", styles["H2"]))
        rows = [["t (s)", "Severity", "Category", "Log line"]]
        for e in runtime_events:
            rows.append([
                _str(e.get("timestamp_in_session")),
                _str(e.get("severity")),
                _trim(_str(e.get("event_category")), 30),
                _trim(_str(e.get("log_line")), 60),
            ])
        story.append(_styled_table(rows, [1.5 * cm, 2 * cm, 5 * cm, 7.5 * cm],
                                   severity_col=1))

    if dynamic_findings:
        story.append(Paragraph("Dynamic findings", styles["H2"]))
        for f in dynamic_findings:
            _append_finding(story, styles, f)

    story.append(PageBreak())


def _build_sbp_section(story, styles, sbp_rules):
    story.append(Paragraph("SBP Cybersecurity Framework Compliance", styles["H1"]))
    if not sbp_rules:
        story.append(Paragraph(
            "SBP compliance was enabled for this analysis but no rule rows "
            "were recorded.", styles["Muted"],
        ))
        story.append(PageBreak())
        return

    counts: dict[str, int] = {}
    for r in sbp_rules:
        counts[r["compliance_status"]] = counts.get(r["compliance_status"], 0) + 1
    summary_parts = [f"{counts.get(k, 0)} {k}" for k in
                     ("COMPLIANT", "NON_COMPLIANT", "MANUAL_REVIEW", "NOT_APPLICABLE")]
    story.append(Paragraph(" &nbsp;|&nbsp; ".join(summary_parts), styles["Body"]))
    story.append(Spacer(1, 6))

    rows = [["Rule", "Status", "Severity", "Evidence"]]
    for r in sbp_rules:
        rows.append([
            _str(r.get("sbp_rule_id")),
            _str(r.get("compliance_status")),
            _str(r.get("severity") or "—"),
            _trim(_str(r.get("evidence")), 80),
        ])
    story.append(_styled_table(rows, [3 * cm, 3 * cm, 2 * cm, 8 * cm]))
    story.append(PageBreak())


def _build_owasp_cwe_section(story, styles, risk):
    story.append(Paragraph("OWASP Mobile Top 10 (2024) + CWE Summary", styles["H1"]))
    if risk["owasp_categories_triggered"]:
        rows = [["ID", "Category"]]
        for mid in risk["owasp_categories_triggered"]:
            rows.append([mid, OWASP_MTW10_2024.get(mid, "—")])
        story.append(_styled_table(rows, [2 * cm, 14 * cm]))
    else:
        story.append(Paragraph("No OWASP categories triggered.", styles["Muted"]))

    story.append(Paragraph("CWE references", styles["H2"]))
    if risk["cwes_triggered"]:
        story.append(Paragraph(
            " &nbsp;&middot;&nbsp; ".join(risk["cwes_triggered"]), styles["Mono"],
        ))
    else:
        story.append(Paragraph("No CWE references attached.", styles["Muted"]))

    story.append(PageBreak())


def _build_audit_appendix(story, styles, audit_entries):
    story.append(Paragraph("Audit Log Appendix (Chain of Custody)", styles["H1"]))
    story.append(Paragraph(
        "Every state change recorded for this analysis, in chronological "
        "order. Together with the APK SHA-256 on the cover page, this "
        "appendix establishes forensic chain of custody.",
        styles["Muted"],
    ))
    story.append(Spacer(1, 8))

    rows = [["Timestamp", "Action", "Details"]]
    for row in forensic.format_audit_for_pdf(audit_entries):
        rows.append([_trim(row[0], 26), _trim(row[1], 30), _trim(row[2], 70)])
    if len(rows) == 1:
        story.append(Paragraph("No audit entries recorded.", styles["Muted"]))
        return
    story.append(_styled_table(rows, [5 * cm, 5 * cm, 7 * cm]))


# --------------------------------------------------------------------------
# Reusable helpers
# --------------------------------------------------------------------------

def _append_finding(story, styles, f):
    severity = (f.get("severity") or "").upper()
    color = _SEV_COLOR.get(severity, _BORDER)
    title = _str(f.get("title"))
    rows = [[Paragraph(f"<b>[{severity}]</b> {title}", styles["Body"])]]

    meta_parts: list[str] = []
    if f.get("category"):
        meta_parts.append(f"Category: {f['category']}")
    if f.get("file_location"):
        loc = f["file_location"]
        if f.get("line_number"):
            loc = f"{loc}:{f['line_number']}"
        meta_parts.append(f"Location: {loc}")
    if f.get("owasp_id"):
        meta_parts.append(f"OWASP: {f['owasp_id']}")
    if f.get("cwe_id"):
        meta_parts.append(f"CWE: {f['cwe_id']}")
    if meta_parts:
        rows.append([Paragraph(" &nbsp;|&nbsp; ".join(meta_parts), styles["Muted"])])

    if f.get("description"):
        rows.append([Paragraph(_str(f["description"]), styles["Body"])])
    if f.get("code_snippet"):
        rows.append([Paragraph(
            _str(f["code_snippet"]).replace("\n", "<br/>"), styles["Mono"],
        )])

    t = Table(rows, colWidths=[16 * cm])
    t.setStyle(TableStyle([
        ("LINEBEFORE", (0, 0), (0, -1), 2, color),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))


def _styled_table(rows, col_widths, *, severity_col: int | None = None) -> Table:
    """Headered data table with optional severity-cell colouring."""
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _BG_HEADER),
        ("TEXTCOLOR",  (0, 0), (-1, 0), _BG_HEADER_TEXT),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("GRID",       (0, 0), (-1, -1), 0.25, _BORDER),
        ("LEFTPADDING",  (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if severity_col is not None:
        for ri in range(1, len(rows)):
            sev = (rows[ri][severity_col] or "").upper()
            if sev in _SEV_COLOR:
                style.append(("TEXTCOLOR", (severity_col, ri),
                              (severity_col, ri), _SEV_COLOR[sev]))
                style.append(("FONTNAME", (severity_col, ri),
                              (severity_col, ri), "Helvetica-Bold"))
    table.setStyle(TableStyle(style))
    return table


def _str(v) -> str:
    return "" if v is None else str(v)


def _trim(s: str, n: int) -> str:
    s = _str(s)
    return s if len(s) <= n else s[: n - 1] + "..."
