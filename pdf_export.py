"""
pdf_export.py — SecureQA Sentinel PDF report generation.

Deliberately decoupled from SQLAlchemy models: build_report_pdf() takes plain
dicts/lists, not ORM objects. This mirrors the separation already used in
llm_report.py (findings formatting is separate from the Flask route / DB
query). Assemble the data in app.py from your real Scan/Finding/Report
models, then hand it to this module.

Usage from app.py:

    from pdf_export import build_report_pdf

    @app.route("/api/scan/<int:scan_id>/export/pdf")
    def export_pdf(scan_id):
        scan = Scan.query.get_or_404(scan_id)
        findings = Finding.query.filter_by(scan_id=scan_id).all()

        # Prefer whichever backend's report is cached; fall back gracefully.
        report = (Report.query.filter_by(scan_id=scan_id, backend="groq").first()
                  or Report.query.filter_by(scan_id=scan_id, backend="ollama").first())

        audit_ok = verify_audit_chain_up_to(scan_id)  # your existing /api/audit/verify logic

        pdf_bytes = build_report_pdf(
            scan={
                "id": scan.id,
                "target": scan.target,
                "created_at": to_iso_utc(scan.created_at),   # reuse your existing helper
                "duration_seconds": scan.duration_seconds,   # adjust field name if different
                "audit_hash": scan.audit_hash,                # adjust field name if different
            },
            findings=[
                {
                    "name": f.name,
                    "severity": f.risk,       # ZAP's "risk" field — adjust if you renamed it
                    "cwe": f.cwe_id,          # adjust field name if different
                }
                for f in findings
            ],
            audit_verified=audit_ok,
            report_text=report.content if report else None,
            report_backend=report.backend if report else None,
        )

        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"secureqa-scan-{scan_id}-report.pdf",
        )

Notes:
- Nothing here touches scanner.py or does any scanning — pure presentation
  layer, generated on-demand (not cached, unlike AI reports — it's cheap).
- Severity strings are matched case-insensitively against
  {"high", "medium", "low", "informational", "info"}; anything else falls
  back to a neutral gray style rather than raising.
"""

from io import BytesIO
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable,
)
from reportlab.lib.enums import TA_LEFT, TA_RIGHT

# ---------------------------------------------------------------------------
# Severity styling — mirrors the color logic already used in App.jsx's
# findings table, kept consistent so the PDF doesn't look like a different
# tool from the dashboard.
# ---------------------------------------------------------------------------
SEVERITY_STYLES = {
    "high":          {"bg": colors.HexColor("#FAECE7"), "fg": colors.HexColor("#712B13")},
    "medium":        {"bg": colors.HexColor("#FAEEDA"), "fg": colors.HexColor("#633806")},
    "low":           {"bg": colors.HexColor("#F1EFE8"), "fg": colors.HexColor("#444441")},
    "informational": {"bg": colors.HexColor("#F1EFE8"), "fg": colors.HexColor("#888780")},
    "info":          {"bg": colors.HexColor("#F1EFE8"), "fg": colors.HexColor("#888780")},
}
DEFAULT_SEVERITY_STYLE = {"bg": colors.HexColor("#F1EFE8"), "fg": colors.HexColor("#5F5E5A")}

FINDINGS_PER_PAGE_ROWS = 22  # rough cap before reportlab just paginates naturally anyway


def _format_display_date(iso_str: str | None) -> str:
    """
    Scan timestamps arrive as raw ISO strings with microsecond precision
    (e.g. '2026-07-06T07:29:38.648545Z', from database.py's to_iso_utc()).
    That's too noisy for a printed report — reformat to something readable.
    Falls back to the raw string unchanged if parsing fails for any reason.
    """
    if not iso_str:
        return "—"
    try:
        cleaned = iso_str[:-1] if iso_str.endswith("Z") else iso_str  # strip trailing Z
        dt = datetime.fromisoformat(cleaned)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return iso_str


def _severity_style(sev: str) -> dict:
    return SEVERITY_STYLES.get((sev or "").strip().lower(), DEFAULT_SEVERITY_STYLE)


def _severity_counts(findings: list[dict]) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in findings:
        key = (f.get("severity") or "").strip().lower()
        if key == "info":
            key = "informational"
        if key in counts:
            counts[key] += 1
    return counts


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", fontName="Helvetica-Bold", fontSize=15,
        leading=18, textColor=colors.HexColor("#111111"),
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle", fontName="Helvetica", fontSize=9,
        leading=12, textColor=colors.HexColor("#888780"),
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", fontName="Helvetica-Bold", fontSize=11,
        leading=14, spaceBefore=14, spaceAfter=6,
        textColor=colors.HexColor("#111111"),
    ))
    styles.add(ParagraphStyle(
        name="MetaLabel", fontName="Helvetica", fontSize=9,
        textColor=colors.HexColor("#888780"),
    ))
    styles.add(ParagraphStyle(
        name="MetaValue", fontName="Helvetica", fontSize=9,
        textColor=colors.HexColor("#111111"), alignment=TA_RIGHT,
    ))
    styles.add(ParagraphStyle(
        name="ReportBody", fontName="Helvetica", fontSize=9.5,
        leading=14.5, textColor=colors.HexColor("#444441"),
    ))
    styles.add(ParagraphStyle(
        name="FooterText", fontName="Helvetica", fontSize=7.5,
        textColor=colors.HexColor("#B4B2A9"),
    ))
    return styles


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#E5E4DD"))
    canvas.line(20 * mm, 15 * mm, doc.pagesize[0] - 20 * mm, 15 * mm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#B4B2A9"))
    canvas.drawString(20 * mm, 10 * mm, "Generated by SecureQA Sentinel")
    canvas.drawRightString(
        doc.pagesize[0] - 20 * mm, 10 * mm, f"Page {canvas.getPageNumber()}"
    )
    canvas.restoreState()


def build_report_pdf(
    scan: dict,
    findings: list[dict],
    audit_verified: bool | None = None,
    report_text: str | None = None,
    report_backend: str | None = None,
) -> bytes:
    """
    Build the scan report PDF and return raw bytes.

    scan: {"id", "target", "created_at" (ISO string), "duration_seconds" (optional),
           "audit_hash" (optional)}
    findings: [{"name", "severity", "cwe" (optional)}, ...]
    audit_verified: True/False if you've checked the hash chain, None if skipped
    report_text: cached AI report content, or None if not generated yet
    report_backend: "ollama" | "groq", or None
    """
    styles = _build_styles()
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=20 * mm, bottomMargin=22 * mm,
        leftMargin=20 * mm, rightMargin=20 * mm,
    )
    story = []

    # --- Header ---
    header_table = Table(
        [[
            Paragraph("SecureQA Sentinel<br/><font size=9 color='#888780'>Vulnerability scan report</font>", styles["ReportTitle"]),
            Paragraph(
                f"Scan #{scan.get('id', '—')}<br/>{_format_display_date(scan.get('created_at'))}",
                ParagraphStyle(name="HeaderRight", parent=styles["MetaValue"], leading=13),
            ),
        ]],
        colWidths=[110 * mm, 60 * mm],
    )
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -1), 1.2, colors.HexColor("#111111")),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 10))

    # --- Meta table ---
    audit_line = "—"
    if scan.get("audit_hash"):
        short_hash = f"{scan['audit_hash'][:8]}...{scan['audit_hash'][-4:]}"
        if audit_verified is True:
            audit_line = f"{short_hash} <font color='#3B6D11'>verified</font>"
        elif audit_verified is False:
            audit_line = f"{short_hash} <font color='#A32D2D'>MISMATCH</font>"
        else:
            audit_line = short_hash

    meta_rows = [["Target", scan.get("target", "—")]]
    if scan.get("duration_seconds") is not None:
        meta_rows.append(["Scan duration", f"{scan['duration_seconds']}s"])
    meta_rows.append(["Audit hash", audit_line])
    meta_table = Table(
        [[Paragraph(k, styles["MetaLabel"]), Paragraph(v, styles["MetaValue"])] for k, v in meta_rows],
        colWidths=[85 * mm, 85 * mm],
    )
    meta_table.setStyle(TableStyle([
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # --- Severity summary ---
    story.append(Paragraph("Severity summary", styles["SectionHeading"]))
    counts = _severity_counts(findings)
    order = [("high", "High"), ("medium", "Medium"), ("low", "Low"), ("informational", "Info")]
    summary_cells = []
    for key, label in order:
        style = _severity_style(key)
        cell = Table(
            [[Paragraph(f"<font size=15><b>{counts[key]}</b></font>", ParagraphStyle(
                name=f"sum_{key}", alignment=1, textColor=style["fg"]))],
             [Paragraph(f"<font size=8>{label.lower()}</font>", ParagraphStyle(
                name=f"sumlbl_{key}", alignment=1, textColor=style["fg"]))]],
            colWidths=[38 * mm],
        )
        cell.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), style["bg"]),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 8),
            ("ROUNDEDCORNERS", [6, 6, 6, 6]),
        ]))
        summary_cells.append(cell)

    summary_row = Table([summary_cells], colWidths=[42.5 * mm] * 4, spaceAfter=14)
    summary_row.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 2), ("RIGHTPADDING", (0, 0), (-1, -1), 2)]))
    story.append(summary_row)
    story.append(Spacer(1, 8))

    # --- Findings table ---
    story.append(Paragraph("Findings", styles["SectionHeading"]))
    if findings:
        header_row = ["Name", "Severity", "CWE"]
        data_rows = [header_row]
        name_style = ParagraphStyle(name="cellname", fontName="Helvetica", fontSize=8.5, leading=11)
        for f in findings:
            sev = (f.get("severity") or "—")
            style = _severity_style(sev)
            sev_pill = Table(
                [[Paragraph(f"<font size=8 color='{style['fg'].hexval().replace('0x', '#')}'>{sev.title()}</font>", name_style)]],
                colWidths=[22 * mm],
            )
            sev_pill.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), style["bg"]),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("ROUNDEDCORNERS", [8, 8, 8, 8]),
            ]))
            data_rows.append([
                Paragraph(f.get("name", "—"), name_style),
                sev_pill,
                f.get("cwe") or "—",
            ])

        findings_table = Table(
            data_rows, colWidths=[95 * mm, 30 * mm, 25 * mm], repeatRows=1,
        )
        findings_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8.5),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#888780")),
            ("LINEBELOW", (0, 0), (-1, 0), 0.75, colors.HexColor("#B4B2A9")),
            ("LINEBELOW", (0, 1), (-1, -2), 0.5, colors.HexColor("#E5E4DD")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(findings_table)
    else:
        story.append(Paragraph("No findings recorded for this scan.", styles["ReportBody"]))

    story.append(Spacer(1, 14))

    # --- AI report ---
    heading_text = "AI-generated report"
    if report_backend:
        heading_text += f" <font size=8 color='#888780'>via {report_backend}</font>"
    story.append(Paragraph(heading_text, styles["SectionHeading"]))

    if report_text:
        report_box = Table(
            [[Paragraph(report_text.replace("\n", "<br/>"), styles["ReportBody"])]],
            colWidths=[150 * mm],
        )
        report_box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1EFE8")),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("ROUNDEDCORNERS", [6, 6, 6, 6]),
        ]))
        story.append(report_box)
    else:
        story.append(Paragraph(
            "No AI report has been generated for this scan yet. Generate one from the "
            "dashboard before exporting to include it here.",
            ParagraphStyle(name="empty_report", parent=styles["ReportBody"], textColor=colors.HexColor("#888780")),
        ))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()