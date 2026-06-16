"""Phase 6 + Phase 11 — ReportLab Platypus PDF report generator.

Phase 6 established the layout: cover, risk summary, findings sections,
OWASP/CWE summary, audit-log appendix.  Phase 11 expands the cover into
five forensic blocks (Tool / Case / Evidence / Environment / Methodology),
adds page-numbered footers, timezone-aware timestamps, and two new
appendices (Chain of Custody and Verification of Evidence Integrity) to
meet ISO/IEC 27037:2012 court-admissibility requirements.

Determinism: pageCompression=0 (grep-able SHA-256) and invariant=True
(frozen /CreationDate, /ModDate, /ID) are preserved from Phase 6 (D-14,
D-15). Two regenerations of the same analysis produce byte-identical PDFs
except for the in-footer generation timestamp.
"""
from __future__ import annotations

import logging
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas as pdfgen_canvas
from reportlab.platypus import (
    PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

import config
from modules import db_manager, educational, forensic, risk_engine
from modules.patterns.owasp_cwe_map import OWASP_MTW10_2024
from modules.patterns.vuln_patterns import VULN_PATTERNS

log = logging.getLogger(__name__)

_SEV_COLOR = {
    "HIGH":   colors.HexColor("#ff4d4f"),
    "MEDIUM": colors.HexColor("#faad14"),
    "LOW":    colors.HexColor("#52c41a"),
}
_ACCENT = colors.HexColor("#00d4ff")
_BORDER = colors.HexColor("#2d3447")
_TEXT_PRIMARY = colors.HexColor("#0d1117")
_TEXT_SECONDARY = colors.HexColor("#57606a")
_BG_HEADER = colors.HexColor("#0a0e1a")
_BG_HEADER_TEXT = colors.HexColor("#e6edf3")

_SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

_PAGE_W, _PAGE_H = A4


def _make_numbered_canvas(generation_stamp: str):
    """Factory that returns a Canvas subclass with the stamp baked in."""

    class _NumberedCanvas(pdfgen_canvas.Canvas):
        """Draws ``Page X of Y`` + generation timestamp on every page."""

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_pages: list = []

        def showPage(self):
            self._saved_pages.append(dict(self.__dict__))
            super().showPage()

        def save(self):
            total = len(self._saved_pages)
            for idx, state in enumerate(self._saved_pages):
                self.__dict__.update(state)
                self._draw_footer(idx + 1, total)
                super().showPage()
            super().save()

        def _draw_footer(self, page_num: int, total: int) -> None:
            self.saveState()
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#57606a"))
            self.drawString(2 * cm, 1.2 * cm, f"Page {page_num} of {total}")
            self.drawRightString(
                _PAGE_W - 2 * cm, 1.2 * cm,
                f"Generated: {generation_stamp}",
            )
            self.restoreState()

    return _NumberedCanvas


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------

def generate(analysis_id: str) -> str:
    """Build the PDF and return the saved path."""
    generation_stamp = forensic.now_iso8601_with_tz()

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
    risk_findings = list(findings) + risk_engine.sbp_findings_as_findings(analysis_id)
    risk = risk_engine.compute_from_findings(risk_findings)

    apk_path = analysis.get("apk_path") or ""
    if Path(apk_path).exists():
        hashes = forensic.compute_multi_hash(apk_path)
    else:
        hashes = {
            "sha256": analysis.get("apk_hash_sha256") or "",
            "sha1": "",
            "md5": "",
        }

    env = forensic.get_software_environment()

    config.REPORTS_PATH.mkdir(parents=True, exist_ok=True)
    out_path = config.REPORTS_PATH / f"{analysis_id}.pdf"

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title=f"SecureAPK Report - {analysis_id}",
        author=config.TOOL_NAME,
        pageCompression=0,
        invariant=True,
    )

    styles = _build_styles()
    story: list = []

    manifest_findings = [f for f in findings if f["phase"] == 2]
    source_findings = [f for f in findings if f["phase"] == 3]
    dynamic_findings = [f for f in findings if f["phase"] == 4]

    _build_cover(story, styles, analysis, hashes, env, generation_stamp)
    _build_executive_summary(story, styles, risk, findings, analysis)
    _build_scope_and_limitations(story, styles, analysis)
    _build_risk_summary(story, styles, risk)
    _build_manifest_section(story, styles, analysis, permissions, exported,
                            manifest_findings)
    _build_source_section(
        story, styles, source_findings,
        educational_enabled=bool(analysis.get("educational_enabled")),
    )
    if analysis.get("dynamic_enabled"):
        _build_dynamic_section(story, styles, runtime_events, dynamic_findings)
    if analysis.get("sbp_enabled"):
        _build_sbp_section(story, styles, sbp_rules)
    _build_owasp_cwe_section(story, styles, risk)
    _build_conclusion(story, styles, risk, analysis)
    _build_chain_of_custody_appendix(story, styles, audit_entries)
    _build_verification_appendix(story, styles, analysis, hashes)

    canvas_cls = _make_numbered_canvas(generation_stamp)
    doc.build(story, canvasmaker=canvas_cls)

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
# Cover page — 5 forensic blocks
# --------------------------------------------------------------------------

def _build_cover(story, styles, analysis, hashes, env, generation_stamp):
    # Block 1: Tool identification
    story.append(Paragraph("SecureAPK", styles["Title"]))
    story.append(Paragraph(
        "Hybrid Static &amp; Dynamic Android Security Analysis Framework",
        styles["Subtitle"],
    ))
    story.append(Paragraph(
        f"Report generated: {generation_stamp}",
        styles["Muted"],
    ))
    story.append(Spacer(1, 14))

    # Block 2: Case identification
    story.append(Paragraph("Case Identification", styles["H2"]))
    analyst = analysis.get("analyst_name") or "Anonymous Analyst"
    case_rows = [
        ["Analysis ID", analysis.get("id", "")[:8].upper()],
        ["Analyst", analyst],
        ["Institution", "Lahore Garrison University, Department of Criminology"],
    ]
    story.append(_cover_table(case_rows))
    story.append(Spacer(1, 10))

    # Block 3: Evidence identification
    story.append(Paragraph("Evidence Identification", styles["H2"]))
    size_bytes = analysis.get("apk_size_bytes") or 0
    size_mb = f"{size_bytes / (1024 * 1024):.1f} MB" if size_bytes else ""
    evidence_rows = [
        ["APK Filename", _str(analysis.get("apk_filename"))],
        ["File Size", f"{size_bytes:,} bytes ({size_mb})"],
        ["SHA-256", hashes.get("sha256", "")],
        ["SHA-1", hashes.get("sha1", "")],
        ["MD5", hashes.get("md5", "")],
        ["Package", _str(analysis.get("package_name"))],
        ["Version", f"{_str(analysis.get('version_name'))} "
                    f"(code {_str(analysis.get('version_code'))})"],
    ]
    t = Table(evidence_rows, colWidths=[4 * cm, 12.5 * cm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("FONTNAME", (1, 2), (1, 4), "Courier-Bold"),  # hash rows
        ("TEXTCOLOR", (1, 2), (1, 2), _ACCENT),        # SHA-256 accent
        ("TEXTCOLOR", (0, 0), (0, -1), _TEXT_SECONDARY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    # Block 4: Software environment
    story.append(Paragraph("Software Environment", styles["H2"]))
    env_rows = [
        ["Host OS", env.get("os", "")],
        ["Python", env.get("python", "")],
        ["Jadx", env.get("jadx", "")],
        ["ADB", env.get("adb", "")],
        ["SecureAPK", env.get("secureapk", "")],
    ]
    story.append(_cover_table(env_rows))
    story.append(Spacer(1, 10))

    # Block 5: Statement of Methodology
    story.append(Paragraph("Statement of Methodology", styles["H2"]))
    dynamic_word = "executed" if analysis.get("dynamic_enabled") else "skipped"
    methodology = (
        f"This report was generated by SecureAPK v{config.TOOL_VERSION}, "
        f"a hybrid static and dynamic security analysis framework. "
        f"The analysis followed a six-phase methodology aligned with "
        f"ISO/IEC 27037:2012 (Guidelines for identification, collection, "
        f"acquisition and preservation of digital evidence). "
        f"Phase 2 inspected the AndroidManifest.xml file using PyAXMLParser. "
        f"Phase 3 decompiled the APK using Jadx and scanned the resulting "
        f"Java source against {len(VULN_PATTERNS)} vulnerability detection patterns spanning "
        f"nine categories. Phase 4 {dynamic_word} dynamic runtime analysis "
        f"in an isolated Android emulator. Phase 5 computed a weighted risk "
        f"score and mapped findings to OWASP Mobile Top 10 (2024) and CWE "
        f"references. Phase 6 generated this report. Every state change "
        f"throughout the analysis is preserved in the Chain of Custody appendix."
    )
    story.append(Paragraph(methodology, styles["Body"]))
    story.append(Spacer(1, 10))

    # Timestamps
    started = forensic.format_iso8601_with_tz(analysis.get("started_at"))
    completed = forensic.format_iso8601_with_tz(analysis.get("completed_at"))
    ts_rows = [
        ["Analysis started", started],
        ["Analysis completed", completed],
        ["Tool version", f"{config.TOOL_NAME} {config.TOOL_VERSION}"],
    ]
    story.append(_cover_table(ts_rows))
    story.append(Spacer(1, 20))

    # Legal disclaimer
    disclaimer = (
        "<i>This report is generated for educational and authorized security "
        "assessment purposes only. The tool operators bear responsibility for "
        "ensuring lawful use. This document does not constitute legal advice.</i>"
    )
    story.append(Paragraph(disclaimer, styles["Muted"]))
    story.append(PageBreak())


def _cover_table(rows):
    """Small label→value table used repeatedly on the cover."""
    t = Table(rows, colWidths=[4 * cm, 12.5 * cm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), _TEXT_SECONDARY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


# --------------------------------------------------------------------------
# Executive Summary + Scope (Phase 12)
# --------------------------------------------------------------------------

def _build_executive_summary(story, styles, risk, findings, analysis):
    story.append(Paragraph("Executive Summary", styles["H1"]))

    classification = risk["classification"]
    score = risk["normalized_score"]
    total = risk["total_findings"]

    high_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")
    med_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "MEDIUM")
    low_count = sum(1 for f in findings if (f.get("severity") or "").upper() == "LOW")

    apk_name = analysis.get("app_name") or analysis.get("apk_filename") or "the APK"
    summary = (
        f"The security analysis of <b>{_str(apk_name)}</b> identified "
        f"<b>{total}</b> findings and assigned an overall risk classification "
        f"of <b>{classification}</b> (score: {score}/100). "
        f"Of these, <b>{high_count}</b> are HIGH severity, "
        f"<b>{med_count}</b> are MEDIUM, and <b>{low_count}</b> are LOW."
    )
    story.append(Paragraph(summary, styles["Body"]))
    story.append(Spacer(1, 10))

    # Severity distribution chart
    story.append(Paragraph("Severity Distribution", styles["H2"]))
    _build_severity_chart(story, high_count, med_count, low_count)
    story.append(Spacer(1, 10))

    # Top issues
    if risk["top_issues"]:
        story.append(Paragraph("Top Issues", styles["H2"]))
        for i, f in enumerate(risk["top_issues"][:3], 1):
            story.append(Paragraph(
                f"{i}. <b>[{f.get('severity', '')}]</b> {_str(f.get('title'))} "
                f"— {_trim(_str(f.get('description')), 120)}",
                styles["Body"],
            ))
        story.append(Spacer(1, 10))

    # OWASP categories triggered
    if risk["owasp_categories_triggered"]:
        cats = ", ".join(
            f"{mid} ({risk['owasp_names'].get(mid, '')})"
            for mid in risk["owasp_categories_triggered"]
        )
        story.append(Paragraph(
            f"<b>OWASP Mobile Top 10 categories triggered:</b> {cats}",
            styles["Body"],
        ))
        story.append(Spacer(1, 10))

    # Recommendation
    if classification == "HIGH":
        rec = "Immediate remediation is recommended before deployment."
    elif classification == "MEDIUM":
        rec = "Address high-severity findings before deployment; review medium-severity items."
    else:
        rec = "The application demonstrates reasonable security posture. Monitor for emerging threats."
    story.append(Paragraph(f"<b>Recommendation:</b> {rec}", styles["Body"]))
    story.append(PageBreak())


def _build_severity_chart(story, high, med, low):
    """Horizontal bar chart using ReportLab Drawing — no external deps."""
    from reportlab.graphics.shapes import Drawing, Rect, String

    total = high + med + low
    if total == 0:
        story.append(Paragraph("No findings to chart.", ParagraphStyle("_", fontSize=9)))
        return

    chart_w = 400
    bar_h = 22
    drawing_h = 3 * (bar_h + 10) + 10
    d = Drawing(chart_w + 100, drawing_h)

    labels = [("HIGH", high, "#ff4d4f"), ("MEDIUM", med, "#faad14"), ("LOW", low, "#52c41a")]
    max_val = max(high, med, low, 1)

    for i, (label, count, color) in enumerate(labels):
        y = drawing_h - (i + 1) * (bar_h + 10)
        d.add(String(0, y + 6, f"{label} ({count})", fontSize=9, fontName="Helvetica-Bold"))
        bar_w = (count / max_val) * (chart_w - 100) if max_val > 0 else 0
        d.add(Rect(90, y, bar_w, bar_h, fillColor=colors.HexColor(color),
                   strokeColor=None))

    story.append(d)


def _build_scope_and_limitations(story, styles, analysis):
    story.append(Paragraph("Scope and Limitations", styles["H1"]))

    dynamic_word = "included" if analysis.get("dynamic_enabled") else "excluded"
    sbp_word = "included" if analysis.get("sbp_enabled") else "excluded"

    scope = (
        f"<b>What was analyzed:</b> Static inspection of AndroidManifest.xml "
        f"(permissions, exported components, security flags), decompiled Java "
        f"source code (regex-based pattern matching across {len(VULN_PATTERNS)} "
        f"vulnerability patterns in 9 categories). "
        f"Dynamic runtime analysis was <b>{dynamic_word}</b>. "
        f"SBP banking compliance check was <b>{sbp_word}</b>."
    )
    story.append(Paragraph(scope, styles["Body"]))
    story.append(Spacer(1, 8))

    limitations = (
        "<b>Limitations:</b> Pattern-based detection may miss obfuscated code "
        "(ProGuard/R8). Native .so libraries are not analyzed. Server-side API "
        "security is out of scope. Dynamic analysis is limited to ADB + logcat "
        "+ monkey runner in an emulated environment (no Frida/Xposed "
        "instrumentation). False positives are possible in regex-based detection."
    )
    story.append(Paragraph(limitations, styles["Body"]))
    story.append(PageBreak())


def _build_findings_summary_table(story, styles, findings, section_name):
    """Summary table at the start of a findings section: Category | Count | Highest Severity."""
    if not findings:
        return
    by_cat: dict[str, list] = {}
    for f in findings:
        by_cat.setdefault(f.get("category", "Uncategorised"), []).append(f)

    rows = [["Category", "Count", "Highest Severity"]]
    for cat in sorted(by_cat):
        items = by_cat[cat]
        highest = "LOW"
        for item in items:
            sev = (item.get("severity") or "").upper()
            if _SEVERITY_RANK.get(sev, 9) < _SEVERITY_RANK.get(highest, 9):
                highest = sev
        rows.append([cat, str(len(items)), highest])
    story.append(Paragraph(f"{section_name} — Summary", styles["H2"]))
    story.append(_styled_table(rows, [7 * cm, 3 * cm, 4 * cm], severity_col=2))
    story.append(Spacer(1, 8))


# --------------------------------------------------------------------------
# Body sections
# --------------------------------------------------------------------------

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

    _build_findings_summary_table(story, styles, manifest_findings, "Manifest Findings")
    story.append(Paragraph(f"Manifest findings ({len(manifest_findings)})", styles["H2"]))
    for f in manifest_findings:
        _append_finding(story, styles, f)
    story.append(PageBreak())


def _build_source_section(story, styles, source_findings, *, educational_enabled: bool = False):
    story.append(Paragraph("Source Code Analysis", styles["H1"]))
    _build_findings_summary_table(story, styles, source_findings, "Source Findings")
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
            if educational_enabled:
                _append_educational_block(story, styles, f)
    story.append(PageBreak())


def _append_educational_block(story, styles, finding):
    rem = educational.get_remediation_for_pattern(finding.get("pattern_id"))
    if not rem:
        return
    vuln_bg = colors.HexColor("#fff1f0")
    fix_bg = colors.HexColor("#f3fff0")
    neutral_bg = colors.HexColor("#f5f7fa")

    def _row(label, body, bg, accent):
        cell = Paragraph(
            f"<b>{label}</b><br/><font face='Courier' size='8'>"
            f"{_str(body).replace('&', '&amp;').replace('<', '&lt;').replace(chr(10), '<br/>')}"
            f"</font>",
            styles["Body"],
        )
        t = Table([[cell]], colWidths=[16 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg),
            ("LINEBEFORE", (0, 0), (0, -1), 2, accent),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        return t

    story.append(_row("Vulnerable", rem["vulnerable_snippet"],
                      vuln_bg, _SEV_COLOR["HIGH"]))
    story.append(_row("Fixed", rem["fixed_snippet"],
                      fix_bg, _SEV_COLOR["LOW"]))
    story.append(_row("Why this matters", rem["explanation"],
                      neutral_bg, _BORDER))
    story.append(Spacer(1, 8))


def _build_dynamic_section(story, styles, runtime_events, dynamic_findings):
    story.append(Paragraph("Dynamic Analysis", styles["H1"]))
    _build_findings_summary_table(story, styles, dynamic_findings, "Dynamic Findings")
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


# --------------------------------------------------------------------------
# Conclusion & Recommendations (Phase 12)
# --------------------------------------------------------------------------

def _build_conclusion(story, styles, risk, analysis):
    story.append(Paragraph("Conclusion and Recommendations", styles["H1"]))

    classification = risk["classification"]
    total = risk["total_findings"]
    score = risk["normalized_score"]
    apk_name = analysis.get("app_name") or analysis.get("apk_filename") or "the APK"

    conclusion = (
        f"The analysis of <b>{_str(apk_name)}</b> produced <b>{total}</b> "
        f"findings with an overall risk classification of <b>{classification}</b> "
        f"(normalized score: {score}/100)."
    )
    story.append(Paragraph(conclusion, styles["Body"]))
    story.append(Spacer(1, 8))

    # Actionable recommendations from top issues
    story.append(Paragraph("Recommendations", styles["H2"]))
    if risk["top_issues"]:
        for i, f in enumerate(risk["top_issues"][:3], 1):
            cat = f.get("category", "")
            sev = f.get("severity", "")
            title = _str(f.get("title"))
            story.append(Paragraph(
                f"{i}. <b>[{sev}] {title}</b> ({cat}) — Review and remediate "
                f"this finding to reduce the application's attack surface.",
                styles["Body"],
            ))
    else:
        story.append(Paragraph(
            "No critical findings requiring immediate attention.",
            styles["Body"],
        ))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"This analysis was performed using SecureAPK v{config.TOOL_VERSION}. "
        f"Results should be validated by a qualified security analyst before "
        f"making deployment decisions.",
        styles["Muted"],
    ))
    story.append(PageBreak())


# --------------------------------------------------------------------------
# Appendix A: Chain of Custody
# --------------------------------------------------------------------------

def _build_chain_of_custody_appendix(story, styles, audit_entries):
    story.append(Paragraph("Appendix A: Chain of Custody", styles["H1"]))
    story.append(Paragraph(
        "Every state change recorded for this analysis, in chronological "
        "order. Together with the APK SHA-256 on the cover page, this "
        "appendix establishes forensic chain of custody.",
        styles["Muted"],
    ))
    story.append(Spacer(1, 8))

    rows = [["Timestamp", "Actor", "Action", "Details"]]
    for e in audit_entries:
        ts = forensic.format_iso8601_with_tz(e.get("timestamp"))
        actor = _str(e.get("actor") or "system")
        action = _str(e.get("action"))
        details_raw = e.get("details")
        if details_raw is None or details_raw == "":
            details = ""
        else:
            try:
                import json
                obj = json.loads(details_raw) if isinstance(details_raw, str) else details_raw
                if isinstance(obj, dict):
                    details = ", ".join(f"{k}={obj[k]}" for k in obj)
                else:
                    details = str(obj)
            except (ValueError, TypeError):
                details = str(details_raw)
        rows.append([ts, actor, action, _trim(details, 60)])

    if len(rows) == 1:
        story.append(Paragraph("No audit entries recorded.", styles["Muted"]))
        return
    story.append(_styled_table(rows, [4.5 * cm, 2 * cm, 4 * cm, 6 * cm]))
    story.append(PageBreak())


# --------------------------------------------------------------------------
# Appendix B: Verification of Evidence Integrity
# --------------------------------------------------------------------------

def _build_verification_appendix(story, styles, analysis, hashes):
    story.append(Paragraph("Appendix B: Verification of Evidence Integrity", styles["H1"]))

    filename = _str(analysis.get("apk_filename"))
    sha256 = hashes.get("sha256", "")

    text = (
        f"To verify the integrity of the analyzed APK file:<br/><br/>"
        f"1. Locate the original APK file.<br/><br/>"
        f"2. Compute its SHA-256 hash using any cryptographic hash tool:<br/>"
        f"&nbsp;&nbsp;&nbsp;&nbsp;<font face='Courier'>sha256sum {filename}</font> "
        f"&nbsp;(Linux/macOS)<br/>"
        f"&nbsp;&nbsp;&nbsp;&nbsp;<font face='Courier'>certutil -hashfile {filename} SHA256</font> "
        f"&nbsp;(Windows)<br/><br/>"
        f"3. Compare the resulting hash to the value printed in the Evidence "
        f"Identification block on the cover page of this report:<br/>"
        f"&nbsp;&nbsp;&nbsp;&nbsp;<font face='Courier'>{sha256}</font><br/><br/>"
        f"4. If the hashes match, the APK file has not been altered since "
        f"analysis was performed. If the hashes differ, evidence integrity "
        f"has been compromised and the report cannot be relied upon.<br/><br/>"
        f"This report was generated with deterministic settings (Phase 6 D-15). "
        f"Re-generating this PDF from the analysis should produce a byte-identical "
        f"document except for the in-footer generation timestamp."
    )
    story.append(Paragraph(text, styles["Body"]))


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
