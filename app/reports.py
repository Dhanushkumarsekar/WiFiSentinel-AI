import io, json
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

def make_pdf(assessment):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    created_time = assessment.get("created_at") or assessment.get("timestamp") or "Unknown"
    story = [Paragraph("WiFiSentinel AI — Wireless Security Assessment", styles["Title"]),
             Paragraph(f"Assessment #{assessment.get('id', 'Live')} · {created_time} · Mode: {assessment.get('mode', 'live').upper()}", styles["Normal"]),
             Spacer(1, 12)]
    s = assessment["summary"]
    story.append(Paragraph(f"Networks assessed: {s.get('networks', 0)} | Findings: {s.get('findings', 0)} | High/Critical: {s.get('high_critical', 0)}", styles["Heading2"]))
    story.append(Spacer(1, 8))
    data = [["Network", "Security", "Risk", "Finding count"]]
    for n in assessment["networks"]:
        data.append([str(n.get("ssid",""))[:32], str(n.get("security",""))[:18], f"{n.get('risk_label')} ({n.get('risk_score')})", str(len(n.get("findings", [])))])
    table = Table(data, repeatRows=1, colWidths=[160, 90, 90, 90])
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#14213d")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.grey),
        ("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f3f5f8")])]))
    story.append(table)
    story.append(Spacer(1, 14))
    story.append(Paragraph("Findings and remediation", styles["Heading1"]))
    for n in assessment["networks"]:
        story.append(Paragraph(f"{n.get('ssid')} — {n.get('security')} — risk {n.get('risk_score')}/100", styles["Heading2"]))
        if not n.get("findings"):
            story.append(Paragraph("No findings from the limited advertised-metadata checks. This is not proof that the network is secure.", styles["BodyText"]))
        for f in n.get("findings", []):
            story.append(Paragraph(f"<b>{f['severity']}: {f['title']}</b> ({f['id']})", styles["BodyText"]))
            story.append(Paragraph(f"Evidence: {f['evidence']}", styles["BodyText"]))
            story.append(Paragraph(f"Recommendation: {f['recommendation']}", styles["BodyText"]))
            story.append(Spacer(1, 6))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Scope limitation: findings are based on observable metadata only. Authenticated router checks are required to assess settings such as firmware version, WPS state, management access controls and client isolation.", styles["Italic"]))
    doc.build(story)
    return buffer.getvalue()
