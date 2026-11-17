"""Flask dashboard for authorized, private-lab network assessments."""
from pathlib import Path
import ipaddress
import json

from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for

from report_generator import create_report
from scanner import ScanError, scan_network, validate_target

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
DATA_FILE = REPORT_DIR / "latest_scan.json"
app = Flask(__name__)
app.secret_key = "local-lab-dashboard-key"
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
REPORT_DIR.mkdir(exist_ok=True)


def load_results():
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
    return None


@app.get("/")
def dashboard():
    return render_template("index.html", results=load_results())


@app.post("/scan")
def start_scan():
    target = request.form.get("target", "").strip()
    try:
        validate_target(target)
        results = scan_network(target)
        DATA_FILE.write_text(json.dumps(results, indent=2), encoding="utf-8")
        create_report(results, REPORT_DIR)
        flash(f"Scan complete: {len(results['hosts'])} active host(s) found.", "success")
    except (ScanError, OSError, ValueError) as exc:
        flash(str(exc), "error")
    return redirect(url_for("dashboard"))


@app.get("/download/<kind>")
def download_report(kind):
    if kind not in {"html", "pdf"}:
        abort(404)
    path = REPORT_DIR / f"assessment_report.{kind}"
    if not path.exists():
        if kind == "pdf" and (REPORT_DIR / "assessment_report.html").exists():
            flash("PDF support is unavailable. Install project dependencies with: pip install -r requirements.txt", "error")
        else:
            flash("Run a scan first to generate a report.", "error")
        return redirect(url_for("dashboard"))
    return send_file(path, as_attachment=True, download_name=path.name)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
