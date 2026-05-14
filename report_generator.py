"""
Report Generator - Creates structured PDF security reports
"""
import os
from datetime import datetime

def generate_pdf_report(data, reports_folder):
    """Generate a PDF security report. Falls back to HTML if reportlab unavailable."""
    os.makedirs(reports_folder, exist_ok=True)
    analysis_id = data.get('analysis_id', 'UNKNOWN')
    pdf_path = os.path.join(reports_folder, f"SecureAPK_Report_{analysis_id}.pdf")

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch, cm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                         TableStyle, HRFlowable, KeepTogether)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

        _generate_reportlab_pdf(data, pdf_path)
        return pdf_path

    except ImportError:
        # Fallback: generate HTML report and save as .pdf named file
        html_path = pdf_path.replace('.pdf', '_report.html')
        _generate_html_report(data, html_path)
        return html_path


def _generate_reportlab_pdf(data, pdf_path):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                     TableStyle, HRFlowable, KeepTogether)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT

    risk = data.get('risk', {})
    manifest = data.get('manifest', {})
    source = data.get('source_code', {})
    dynamic = data.get('dynamic', {})

    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                             rightMargin=2*cm, leftMargin=2*cm,
                             topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle('Title', fontSize=20, leading=24,
                                  textColor=colors.HexColor('#0f172a'),
                                  spaceAfter=4, fontName='Helvetica-Bold',
                                  alignment=TA_CENTER)
    subtitle_style = ParagraphStyle('Sub', fontSize=11, leading=14,
                                     textColor=colors.HexColor('#64748b'),
                                     spaceAfter=2, alignment=TA_CENTER)
    h2_style = ParagraphStyle('H2', fontSize=14, leading=18,
                               textColor=colors.HexColor('#1e293b'),
                               spaceBefore=14, spaceAfter=6,
                               fontName='Helvetica-Bold')
    h3_style = ParagraphStyle('H3', fontSize=11, leading=14,
                               textColor=colors.HexColor('#334155'),
                               spaceBefore=8, spaceAfter=4,
                               fontName='Helvetica-Bold')
    body_style = ParagraphStyle('Body', fontSize=9, leading=13,
                                 textColor=colors.HexColor('#374151'),
                                 spaceAfter=4)
    code_style = ParagraphStyle('Code', fontSize=8, leading=11,
                                 fontName='Courier',
                                 textColor=colors.HexColor('#1e293b'),
                                 backColor=colors.HexColor('#f1f5f9'),
                                 spaceAfter=4)

    SEVERITY_COLORS = {
        'HIGH':   colors.HexColor('#fef2f2'),
        'MEDIUM': colors.HexColor('#fffbeb'),
        'LOW':    colors.HexColor('#f0fdf4'),
    }
    SEVERITY_BORDER = {
        'HIGH':   colors.HexColor('#ef4444'),
        'MEDIUM': colors.HexColor('#f59e0b'),
        'LOW':    colors.HexColor('#22c55e'),
    }

    elements = []

    # ── Cover ──
    elements.append(Spacer(1, 0.5*cm))
    elements.append(Paragraph("SecureAPK", title_style))
    elements.append(Paragraph("Hybrid Static & Dynamic Android Security Report", subtitle_style))
    elements.append(Spacer(1, 0.3*cm))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3b82f6')))
    elements.append(Spacer(1, 0.3*cm))

    # Meta table
    meta = manifest.get('metadata', {})
    ts = data.get('timestamp', datetime.now().isoformat())[:19].replace('T', ' ')
    meta_data = [
        ['Analysis ID', data.get('analysis_id', 'N/A'), 'Report Date', ts],
        ['APK File', data.get('filename', 'N/A'), 'Package', meta.get('package_name', 'N/A')],
        ['Version', meta.get('version_name', 'N/A'), 'Min SDK', meta.get('min_sdk', 'N/A')],
    ]
    meta_table = Table(meta_data, colWidths=[3.5*cm, 6*cm, 3*cm, 5*cm])
    meta_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#64748b')),
        ('TEXTCOLOR', (2, 0), (2, -1), colors.HexColor('#64748b')),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.3, colors.HexColor('#e2e8f0')),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 0.5*cm))

    # ── Risk Summary ──
    level = risk.get('level', 'UNKNOWN')
    score = risk.get('score', 0)
    risk_color_map = {'HIGH': colors.HexColor('#fef2f2'), 'MEDIUM': colors.HexColor('#fffbeb'), 'LOW': colors.HexColor('#f0fdf4')}
    risk_border_map = {'HIGH': colors.HexColor('#ef4444'), 'MEDIUM': colors.HexColor('#f59e0b'), 'LOW': colors.HexColor('#22c55e')}
    sev = risk.get('severity_counts', {})

    risk_data = [
        [Paragraph(f'<b>Overall Risk: {level}</b>', ParagraphStyle('risk', fontSize=16, textColor=risk_border_map.get(level, colors.black), fontName='Helvetica-Bold')),
         Paragraph(f'<b>Score: {score}/100</b>', ParagraphStyle('score', fontSize=14, textColor=colors.HexColor('#1e293b'), fontName='Helvetica-Bold'))],
        [Paragraph(risk.get('recommendation', ''), body_style), ''],
        [Paragraph(f'HIGH: {sev.get("HIGH",0)}  |  MEDIUM: {sev.get("MEDIUM",0)}  |  LOW: {sev.get("LOW",0)}  |  Total: {risk.get("total_findings",0)}', body_style), ''],
    ]
    risk_table = Table(risk_data, colWidths=[12*cm, 5.5*cm])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), risk_color_map.get(level, colors.white)),
        ('BOX', (0, 0), (-1, -1), 2, risk_border_map.get(level, colors.gray)),
        ('SPAN', (0, 1), (1, 1)),
        ('SPAN', (0, 2), (1, 2)),
        ('PADDING', (0, 0), (-1, -1), 10),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 0.4*cm))

    # ── Score Breakdown ──
    elements.append(Paragraph("Risk Score Breakdown", h2_style))
    bd = risk.get('breakdown', {})
    bd_data = [
        ['Module', 'Findings', 'Score Contribution'],
        ['Manifest Analysis', str(bd.get('manifest', {}).get('count', 0)), str(bd.get('manifest', {}).get('score', 0))],
        ['Source Code Analysis', str(bd.get('source_code', {}).get('count', 0)), str(bd.get('source_code', {}).get('score', 0))],
        ['Dynamic Analysis', str(bd.get('dynamic', {}).get('count', 0)), str(bd.get('dynamic', {}).get('score', 0))],
    ]
    bd_table = Table(bd_data, colWidths=[9*cm, 4*cm, 4.5*cm])
    bd_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f8fafc'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.3, colors.HexColor('#e2e8f0')),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
    ]))
    elements.append(bd_table)
    elements.append(Spacer(1, 0.3*cm))

    # ── Helper: findings table ──
    def findings_section(title, findings_list):
        if not findings_list:
            return
        elements.append(Paragraph(title, h2_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
        for f in findings_list[:30]:  # Cap at 30 per section
            sev = f.get('severity', 'LOW')
            bg = SEVERITY_COLORS.get(sev, colors.white)
            border_col = SEVERITY_BORDER.get(sev, colors.gray)
            detail = f.get('detail', f.get('matched', ''))
            snippet = f.get('snippet', f.get('evidence', ''))
            row = [
                [Paragraph(f'[{sev}] {f.get("title","")}', h3_style),
                 Paragraph(f.get('description', ''), body_style),
                 Paragraph(f'Location: {detail}', code_style) if detail else Spacer(1, 1),
                 Paragraph(f'Evidence: {snippet[:100]}', code_style) if snippet else Spacer(1, 1)]
            ]
            t = Table([[Paragraph(f'[{sev}] {f.get("title","")}', ParagraphStyle("fh", fontSize=10, fontName="Helvetica-Bold", textColor=border_col)),
                        Paragraph(f.get("category",""), ParagraphStyle("cat", fontSize=8, textColor=colors.HexColor("#64748b")))],
                       [Paragraph(f.get('description', ''), body_style), ''],
                       [Paragraph(f'📁 {detail}', code_style) if detail else Spacer(1,1), ''],
                       ], colWidths=[13*cm, 4.5*cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), bg),
                ('BOX', (0, 0), (-1, -1), 1, border_col),
                ('SPAN', (0, 1), (-1, 1)),
                ('SPAN', (0, 2), (-1, 2)),
                ('PADDING', (0, 0), (-1, -1), 7),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(KeepTogether([t, Spacer(1, 0.2*cm)]))

    # ── Manifest Findings ──
    findings_section("Phase 2: Manifest Analysis Findings", manifest.get('findings', []))

    # ── Source Code Findings ──
    findings_section("Phase 3: Source Code Vulnerability Findings", source.get('findings', []))

    # ── Dynamic Findings ──
    if dynamic.get('status') == 'success':
        findings_section("Phase 4: Dynamic Analysis Findings", dynamic.get('suspicious_events', []))
    else:
        elements.append(Paragraph("Phase 4: Dynamic Analysis", h2_style))
        msg = dynamic.get('message', dynamic.get('error', 'Dynamic analysis was not performed.'))
        elements.append(Paragraph(msg, body_style))

    # ── OWASP / CWE ──
    owasp = risk.get('owasp_references', [])
    cwe = risk.get('cwe_references', [])
    if owasp or cwe:
        elements.append(Paragraph("Security Standards References", h2_style))
        if owasp:
            elements.append(Paragraph("OWASP Mobile Top 10 (2024) Mapped:", h3_style))
            for ref in owasp:
                elements.append(Paragraph(f"• {ref['code']} — {ref['name']}", body_style))
        if cwe:
            elements.append(Paragraph("CWE References:", h3_style))
            for ref in cwe:
                elements.append(Paragraph(f"• {ref['cwe']} — {ref['title']}", body_style))

    # ── Footer note ──
    elements.append(Spacer(1, 0.5*cm))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e2e8f0')))
    elements.append(Paragraph(
        f"Generated by SecureAPK | Lahore Garrison University FYP | {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        ParagraphStyle('footer', fontSize=7, textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER)
    ))

    doc.build(elements)


def _generate_html_report(data, html_path):
    """Fallback HTML report"""
    risk = data.get('risk', {})
    manifest = data.get('manifest', {})
    source = data.get('source_code', {})
    dynamic = data.get('dynamic', {})
    level = risk.get('level', 'UNKNOWN')
    score = risk.get('score', 0)
    sev = risk.get('severity_counts', {})

    color_map = {'HIGH': '#ef4444', 'MEDIUM': '#f59e0b', 'LOW': '#22c55e'}
    rc = color_map.get(level, '#94a3b8')
    bg_map = {'HIGH': '#fef2f2', 'MEDIUM': '#fffbeb', 'LOW': '#f0fdf4'}
    header_bg = bg_map.get(level, '#f8fafc')

    all_findings = manifest.get('findings', []) + source.get('findings', []) + dynamic.get('suspicious_events', [])

    rows = ''
    for f in all_findings:
        sev_f = f.get('severity', 'LOW')
        row_bg = bg_map.get(sev_f, 'white')
        sev_color = color_map.get(sev_f, '#94a3b8')
        title = f.get('title', '')
        category = f.get('category', '')
        description = f.get('description', '')
        detail = f.get('detail', f.get('evidence', ''))[:80]
        rows += (
            f'<tr style="background:{row_bg}">'
            f'<td><span style="color:{sev_color};font-weight:bold">{sev_f}</span></td>'
            f'<td>{title}</td>'
            f'<td>{category}</td>'
            f'<td style="font-size:12px">{description}</td>'
            f'<td style="font-family:monospace;font-size:11px">{detail}</td>'
            f'</tr>'
        )

    recommendation = risk.get('recommendation', '')
    analysis_id = data.get('analysis_id', '')
    filename = data.get('filename', '')
    timestamp = data.get('timestamp', '')[:19]
    high_count = sev.get('HIGH', 0)
    medium_count = sev.get('MEDIUM', 0)
    low_count = sev.get('LOW', 0)
    total_findings = risk.get('total_findings', 0)
    gen_time = datetime.now().strftime('%Y-%m-%d %H:%M')

    html = (
        '<!DOCTYPE html>'
        '<html><head><meta charset="UTF-8"><title>SecureAPK Report</title>'
        '<style>'
        'body{font-family:sans-serif;margin:40px;color:#1e293b}'
        'table{border-collapse:collapse;width:100%}'
        'th{background:#1e293b;color:white;padding:10px;text-align:left}'
        'td{padding:8px;border-bottom:1px solid #e2e8f0}'
        'h1{color:#0f172a}h2{color:#1e293b;border-bottom:2px solid #3b82f6;padding-bottom:6px}'
        '</style>'
        '</head><body>'
        '<h1>SecureAPK Security Report</h1>'
        f'<p><b>Analysis ID:</b> {analysis_id} | <b>File:</b> {filename} | <b>Date:</b> {timestamp}</p>'
        f'<div style="background:{header_bg};border:3px solid {rc};padding:20px;border-radius:8px;margin:20px 0">'
        f'<h2 style="margin:0;color:{rc}">Risk Level: {level} — Score: {score}/100</h2>'
        f'<p>{recommendation}</p>'
        f'<p>HIGH: {high_count} | MEDIUM: {medium_count} | LOW: {low_count} | Total: {total_findings}</p>'
        '</div>'
        '<h2>All Findings</h2>'
        '<table><tr><th>Severity</th><th>Title</th><th>Category</th><th>Description</th><th>Location</th></tr>'
        f'{rows}'
        '</table>'
        f'<hr><p style="color:#94a3b8;font-size:12px">Generated by SecureAPK | Lahore Garrison University FYP | {gen_time}</p>'
        '</body></html>'
    )

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)
