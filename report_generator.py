"""Build a self-contained HTML report and a PDF when ReportLab is installed."""
from html import escape
from pathlib import Path

RISK_PORTS = {
    21: ("High", "FTP may expose credentials or files without encryption."),
    23: ("High", "Telnet sends session data without encryption."),
    445: ("High", "SMB is sensitive to exposure and should be limited to trusted networks."),
    3389: ("Medium", "Remote Desktop should be restricted to trusted hosts and protected with strong authentication."),
    5900: ("Medium", "VNC remote access should be restricted and protected."),
    22: ("Low", "SSH is a remote administration service; limit access and use key-based authentication."),
    80: ("Low", "HTTP traffic is unencrypted; use HTTPS for sensitive web applications."),
}


def findings_for(results):
    findings = []
    for host in results.get("hosts", []):
        for port in host.get("ports", []):
            risk = RISK_PORTS.get(port["port"])
            if risk:
                severity, note = risk
                findings.append({"host": host["ip"], "port": port["port"], "service": port["service"],
                                 "severity": severity, "finding": note})
    return findings


def _topology(results):
    nodes = ["<div class='network'>" + escape(results["target"]) + "</div>"]
    nodes += [f"<div class='host'><strong>{escape(h['ip'])}</strong><br>{escape(h.get('hostname') or 'Host')}<br>"
              f"{len(h.get('ports', []))} open port(s)</div>" for h in results.get("hosts", [])]
    if len(nodes) == 1:
        nodes.append("<div class='host'>No active hosts discovered</div>")
    return "<div class='topology'>" + "".join(nodes) + "</div>"


def report_html(results):
    findings = findings_for(results)
    host_rows = []
    for host in results.get("hosts", []):
        ports = ", ".join(f"{p['port']}/{p['protocol']} {p['service']} {p.get('product','')} {p.get('version','')}".strip()
                           for p in host.get("ports", [])) or "No open ports in the scanned set"
        host_rows.append("<tr><td>" + escape(host["ip"]) + "</td><td>" + escape(host.get("hostname") or "—") +
                         "</td><td>" + escape(host.get("os", "Not determined")) + "</td><td>" + escape(ports) + "</td></tr>")
    finding_rows = ["<tr><td>" + escape(f["severity"]) + "</td><td>" + escape(f["host"]) + "</td><td>" +
                    str(f["port"]) + "/" + escape(f["service"]) + "</td><td>" + escape(f["finding"]) + "</td></tr>"
                    for f in findings]
    if not finding_rows:
        finding_rows = ["<tr><td colspan='4'>No ports in the project's watch list were found.</td></tr>"]
    recommendations = ["Confirm each exposed service is required and firewall it to approved systems.",
                       "Prefer encrypted administration and web protocols; disable legacy services where possible.",
                       "Keep operating systems and service software patched, and repeat scans after changes.",
                       "A port scan is an indicator only; manually validate findings with the system owner."]
    rec_html = "".join("<li>" + escape(item) + "</li>" for item in recommendations)
    return f"""<!doctype html><html lang='en'><meta charset='utf-8'><title>Network Security Assessment</title>
<style>body{{font:15px Arial,sans-serif;max-width:1050px;margin:35px auto;padding:0 20px;color:#172033}}h1{{color:#123b5d}}table{{border-collapse:collapse;width:100%;margin:18px 0}}th,td{{padding:10px;border:1px solid #d7e0e8;text-align:left;vertical-align:top}}th{{background:#eaf2f8}}.topology{{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0}}.network,.host{{border:1px solid #9bb6c9;border-radius:8px;padding:14px;background:#f4f8fb}}.network{{font-weight:bold}}.note{{color:#526273;font-size:13px}}</style>
<h1>Network Reconnaissance and Security Assessment</h1><p><b>Target:</b> {escape(results['target'])} &nbsp; <b>Scanned:</b> {escape(results['scanned_at'])}</p>
<p class='note'>Authorized lab assessment. Nmap discovery and a top 100 TCP port, light service-version scan. OS identification depends on Nmap privileges and host response.</p>
<h2>Network topology</h2>{_topology(results)}<h2>Host and service results</h2>
<table><tr><th>IP address</th><th>Hostname</th><th>OS estimate</th><th>Open ports and services</th></tr>{''.join(host_rows) or '<tr><td colspan="4">No active hosts discovered.</td></tr>'}</table>
<h2>Security findings</h2><table><tr><th>Severity</th><th>Host</th><th>Port/service</th><th>Observation</th></tr>{''.join(finding_rows)}</table>
<h2>Recommendations</h2><ol>{rec_html}</ol><p class='note'>Risk labels are simple educational indicators, not a full vulnerability assessment. Only scan systems for which you have explicit authorization.</p></html>"""


def create_report(results, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    html_path = output_dir / "assessment_report.html"
    html_path.write_text(report_html(results), encoding="utf-8")
    # Optional dependency: keep the main application usable without a PDF library.
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        return html_path
    pdf_path = output_dir / "assessment_report.pdf"
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(pdf_path), pagesize=letter)
    story = [Paragraph("Network Reconnaissance and Security Assessment", styles["Title"]),
             Paragraph(f"Target: {escape(results['target'])}<br/>Scanned: {escape(results['scanned_at'])}", styles["BodyText"]), Spacer(1, 14),
             Paragraph("Host and service results", styles["Heading2"])]
    data = [["Host", "OS estimate", "Open ports/services"]]
    for h in results.get("hosts", []):
        ports = ", ".join(f"{p['port']} {p['service']}" for p in h.get("ports", [])) or "None observed"
        data.append([h["ip"], h.get("os", "Not determined"), ports])
    table = Table(data, repeatRows=1, colWidths=[100, 130, 290])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf2f8")), ("GRID", (0, 0), (-1, -1), .5, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.extend([table, Spacer(1, 14), Paragraph("Security findings", styles["Heading2"])])
    for f in findings_for(results):
        story.append(Paragraph(f"{f['severity']} — {f['host']}:{f['port']} ({escape(f['service'])}): {escape(f['finding'])}", styles["BodyText"]))
        story.append(Spacer(1, 5))
    story.extend([Spacer(1, 10), Paragraph("Recommendations", styles["Heading2"])])
    for rec in ["Confirm exposed services are required and restrict them to approved systems.", "Prefer encrypted protocols; disable legacy services where possible.", "Keep systems patched and validate observations with the system owner."]:
        story.append(Paragraph("• " + rec, styles["BodyText"]))
    doc.build(story)
    return html_path
