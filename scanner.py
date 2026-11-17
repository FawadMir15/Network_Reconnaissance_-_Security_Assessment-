"""Small, conservative Nmap wrapper for private IPv4 lab ranges."""
from datetime import datetime, timezone
import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET


class ScanError(RuntimeError):
    """Actionable scanning or configuration error."""


def validate_target(target):
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ScanError("Enter a valid IPv4 address or CIDR range, such as 192.168.56.0/24.") from exc
    if network.version != 4 or not (network.is_private or network.is_loopback):
        raise ScanError("For safety, this project only scans private or loopback IPv4 networks.")
    if network.num_addresses > 256:
        raise ScanError("The scan is limited to 256 addresses. Enter a smaller lab subnet.")
    return network


def _run_nmap(args, timeout=180):
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ScanError("Nmap timed out. Try a smaller subnet or check connectivity.") from exc
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ScanError(f"Nmap could not complete the scan: {detail[:350]}")
    try:
        return ET.fromstring(completed.stdout)
    except ET.ParseError as exc:
        raise ScanError("Nmap returned unreadable scan data.") from exc


def _read_hosts(root):
    hosts = []
    for node in root.findall("host"):
        status = node.find("status")
        if status is None or status.get("state") != "up":
            continue
        addresses = node.findall("address")
        ipv4 = next((a.get("addr") for a in addresses if a.get("addrtype") == "ipv4"), "unknown")
        mac = next((a.get("addr") for a in addresses if a.get("addrtype") == "mac"), "")
        vendor = next((a.get("vendor", "") for a in addresses if a.get("addrtype") == "mac"), "")
        names = node.findall("./hostnames/hostname")
        hosts.append({"ip": ipv4, "hostname": names[0].get("name", "") if names else "", "mac": mac,
                      "vendor": vendor, "os": "Not determined", "ports": []})
    return hosts


def scan_network(target):
    network = validate_target(target)
    binary = shutil.which("nmap")
    if not binary:
        raise ScanError("Nmap was not found. Install it with: sudo apt install nmap")
    # Discovery is a separate pass so the port scan is limited to active hosts.
    discovery = _run_nmap([binary, "-sn", "-oX", "-", str(network)], timeout=120)
    hosts = _read_hosts(discovery)
    if hosts:
        active_ips = [host["ip"] for host in hosts]
        service_root = _run_nmap([binary, "-sT", "-sV", "-O", "--version-light", "--top-ports", "100",
                                  "--open", "-oX", "-", *active_ips], timeout=240)
        by_ip = {h["ip"]: h for h in hosts}
        for node in service_root.findall("host"):
            address = node.find("./address[@addrtype='ipv4']")
            if address is None or address.get("addr") not in by_ip:
                continue
            host = by_ip[address.get("addr")]
            osmatch = node.find("./os/osmatch")
            if osmatch is not None:
                host["os"] = osmatch.get("name", "Not determined")
            for port in node.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                host["ports"].append({"port": int(port.get("portid")), "protocol": port.get("protocol", "tcp"),
                                      "service": service.get("name", "unknown") if service is not None else "unknown",
                                      "product": service.get("product", "") if service is not None else "",
                                      "version": service.get("version", "") if service is not None else ""})
    return {"target": str(network), "scanned_at": datetime.now(timezone.utc).isoformat(),
            "hosts": sorted(hosts, key=lambda item: ipaddress.ip_address(item["ip"]))}
