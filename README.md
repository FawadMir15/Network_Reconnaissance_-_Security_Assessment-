# Network Reconnaissance and Security Assessment

A beginner-friendly Flask dashboard for authorized reconnaissance of a small private IPv4 lab. It uses Nmap for host discovery and a conservative top-100 TCP port scan with light service/version detection, then creates an HTML report and (when ReportLab is installed) a PDF report.

## Safety and scope

Use only on networks and devices for which you have explicit authorization. The app accepts only private or loopback IPv4 targets and caps a scan at 256 addresses. It does not exploit services, attempt passwords, or run denial-of-service tests. The findings are educational watch-list indicators, not vulnerability confirmation.

## Requirements

- Kali Linux or another Linux environment with Python 3.10+ and Nmap.
- On Kali: `sudo apt update && sudo apt install -y python3 python3-venv nmap`
- `sudo` is not required to run Flask. Nmap OS detection may not work without elevated privileges and can remain “Not determined.”

## Install and run

```bash
cd network-recon-assessment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`, enter a lab target such as `192.168.56.0/24`, and press **Start Scan**. Use the HTML or PDF download buttons after the scan. Stop the local server with Ctrl+C.

For a safe self-check, scan `127.0.0.1` on a machine you control. A virtual lab subnet is preferable for a class demonstration. Netdiscover can be used independently on Kali for ARP-based discovery (for example `sudo netdiscover -r 192.168.56.0/24`); this project uses Nmap discovery so it works across routed lab interfaces too. Wireshark may be used to observe the authorized scan traffic on the lab interface.

## Project layout

- `app.py` — Flask routes, dashboard state, input handling, downloads.
- `scanner.py` — target validation, safe Nmap subprocess calls, XML parsing.
- `report_generator.py` — topology, watch-list findings, recommendations, HTML/PDF exports.
- `templates/index.html` and `static/style.css` — responsive dashboard.
- `reports/` — generated scan data and downloadable reports.
- `sample_results.json` — offline example results for a presentation; never treated as live scan data.

## Scan steps

1. Nmap `-sn` discovers active hosts on the validated subnet.
2. Nmap `-sT -sV --version-light --top-ports 100 --open` checks active hosts only.
3. The report lists host addresses, available names/MAC vendors, OS estimate when returned, open services, and simple risk watch-list observations.

The dashboard binds to localhost only. For real lab scans, run it on Kali with network access to the lab. Report files are local and should be handled according to your course or lab rules.
