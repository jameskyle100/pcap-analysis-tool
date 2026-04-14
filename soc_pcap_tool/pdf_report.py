from __future__ import annotations

from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

from .constants import SCRIPT_COPYRIGHT

def generate_summary_pdf(report: dict[str, Any]) -> BytesIO:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=16 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        textColor=colors.white,
        alignment=TA_LEFT,
        spaceAfter=6,
    )

    badge_style = ParagraphStyle(
        "BadgeStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        textColor=colors.HexColor("#FECACA"),
        backColor=colors.HexColor("#7F1D1D"),
        alignment=TA_LEFT,
        spaceAfter=8,
    )

    section_title_style = ParagraphStyle(
        "SectionTitle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        textColor=colors.white,
        spaceAfter=8,
    )

    normal_style = ParagraphStyle(
        "NormalBlue",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#E2E8F0"),
        spaceAfter=4,
    )

    finding_title_style = ParagraphStyle(
        "FindingTitle",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=11,
        textColor=colors.white,
        spaceAfter=4,
    )

    recommendation_style = ParagraphStyle(
        "RecommendationStyle",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#E2E8F0"),
        spaceAfter=0,
    )

    story: list[Any] = []

    header_badge = Table([[Paragraph("FORMAL REPORT", badge_style)]], colWidths=[180 * mm])
    header_badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F2D5C")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1E3A5F")),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(header_badge)

    header_title = Table([[Paragraph("Analysis Summary", title_style)]], colWidths=[180 * mm])
    header_title.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F2D5C")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#1E3A5F")),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(header_title)
    story.append(Spacer(1, 8))

    summary = report.get("summary", {})
    findings = report.get("findings", [])
    takeaways = report.get("analyst_takeaway", [])
    hosts = report.get("host_summary", [])

    def section_box(title: str, inner_flowables: list[Any]) -> Table:
        rows = [[Paragraph(title, section_title_style)]]
        for item in inner_flowables:
            rows.append([item])
        table = Table(rows, colWidths=[180 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0F172A")),
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#22324D")),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        return table

    def kv_table(items: list[tuple[str, str]]) -> Table:
        rows: list[list[Any]] = []
        for i in range(0, len(items), 2):
            left = items[i]
            right = items[i + 1] if i + 1 < len(items) else ("", "")
            rows.append([
                Paragraph(f"<font color='#93C5FD'>{left[0]}</font><br/><font color='white'><b>{left[1]}</b></font>", normal_style),
                Paragraph(f"<font color='#93C5FD'>{right[0]}</font><br/><font color='white'><b>{right[1]}</b></font>", normal_style),
            ])
        t = Table(rows, colWidths=[88 * mm, 88 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#08111F")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#24364F")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#24364F")),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        return t

    executive_items = [
        ("Analyzed File", str(report.get("fileName", "-"))),
        ("Mode", str(summary.get("mode", "-"))),
        ("Risk Rating", str(summary.get("triage_rating", "informational")).upper()),
        ("Triage Score", str(summary.get("triage_score", 0))),
        ("Packets", str(summary.get("packet_count", 0))),
        ("Findings", str(summary.get("finding_count", 0))),
    ]
    story.append(section_box("Executive Overview", [kv_table(executive_items)]))
    story.append(Spacer(1, 8))

    takeaway_lines = takeaways or ["No immediate high-signal takeaway generated."]
    story.append(section_box("Analyst Takeaway", [Paragraph(f"• {line}", normal_style) for line in takeaway_lines]))
    story.append(Spacer(1, 8))

    finding_flowables: list[Any] = []
    if findings:
        for f in findings[:8]:
            sev = str(f.get("severity", "info")).lower()
            border_color = {
                "critical": "#B91C1C",
                "high": "#DC2626",
                "medium": "#F59E0B",
                "low": "#22C55E",
                "info": "#3B82F6",
            }.get(sev, "#3B82F6")

            ft = Table([
                [Paragraph(f"<font color='white'><b>{sev.upper()} — {f.get('title', '-')}</b></font>", finding_title_style)],
                [Paragraph(str(f.get("why_it_matters", "-")), normal_style)],
                [Paragraph(f"<font color='#FCA5A5'><b>Next step:</b></font> {f.get('next_step', '-')}", normal_style)],
            ], colWidths=[176 * mm])

            ft.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#08111F")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#24364F")),
                ("LINEBEFORE", (0, 0), (0, -1), 4, colors.HexColor(border_color)),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))
            finding_flowables.append(ft)
            finding_flowables.append(Spacer(1, 6))
    else:
        finding_flowables.append(Paragraph("No notable findings detected by current heuristics.", normal_style))

    story.append(section_box("Priority Findings", finding_flowables))
    story.append(Spacer(1, 8))

    host_lines = []
    for h in hosts[:5]:
        ext = ", ".join([f"{ip} ({count})" for ip, count in h.get("top_external_destinations", [])]) or "none"
        host_lines.append(
            f"• <b>{h.get('source_ip', '-')}</b> — packets: {h.get('packet_count', 0)}, "
            f"bytes: {h.get('bytes_sent', 0)}, external: {ext}"
        )
    if not host_lines:
        host_lines = ["• No host summary available."]
    story.append(section_box("Most Relevant Hosts", [Paragraph(line, normal_style) for line in host_lines]))
    story.append(Spacer(1, 8))

    metric_items = [
        ("Top Protocol", str(summary.get("top_protocol", "-"))),
        ("Unique Source IPs", str(summary.get("unique_source_ips", 0))),
        ("Unique Destination IPs", str(summary.get("unique_destination_ips", 0))),
        ("Average Packet Size", str(summary.get("avg_packet_size", 0))),
        ("Median Packet Size", str(summary.get("median_packet_size", 0))),
        ("Capture Window", f"{summary.get('first_seen_utc', '-')} to {summary.get('last_seen_utc', '-')}"),
    ]
    story.append(section_box("Capture Metrics", [kv_table(metric_items)]))
    story.append(Spacer(1, 8))

    recommendation = Paragraph(
        "<font color='#FCA5A5'><b>Recommendation:</b></font> "
        "Validate the priority findings against EDR, proxy, DNS, and firewall telemetry, "
        "then pivot to the most active hosts and suspicious external destinations for confirmation.",
        recommendation_style,
    )
    rec_table = Table([[recommendation]], colWidths=[180 * mm])
    rec_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#09111F")),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#22324D")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(rec_table)

    def add_pdf_footer(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#6B7280"))
        footer_text = f"{SCRIPT_COPYRIGHT} Unauthorized copying or redistribution is prohibited."
        canvas.drawString(14 * mm, 8 * mm, footer_text)
        canvas.restoreState()

    doc.build(story, onFirstPage=add_pdf_footer, onLaterPages=add_pdf_footer)
    buffer.seek(0)
    return buffer