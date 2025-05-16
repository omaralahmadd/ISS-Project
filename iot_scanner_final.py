#!/usr/bin/env python3
import subprocess
import re

def detect_anomalies(open_ports):
    issues = []
    if 23 in open_ports:
        issues.append("⚠️ Telnet is open (port 23)")
    if 21 in open_ports:
        issues.append("⚠️ FTP is open (port 21)")
    if 80 in open_ports and 443 not in open_ports:
        issues.append("⚠️ HTTP is open but HTTPS (443) is not")
    if 52869 in open_ports:
        issues.append("⚠️ UPnP (port 52869) is exposed")
    return issues

def estimate_risk(issues):
    for issue in issues:
        if "Telnet" in issue or "UPnP" in issue:
            return "High"
    if len(issues) > 0:
        return "Medium"
    return "Low"

def scan_ip(ip):
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-Pn", ip],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except Exception as e:
        print("There was a problem running nmap:", e)
        return None

def get_open_ports(nmap_output):
    ports = []
    for line in nmap_output.splitlines():
        # Lines like "80/tcp  open  http"
        match = re.match(r"^(\d+)/tcp\s+open", line)
        if match:
            ports.append(int(match.group(1)))
    return ports

def main():
    print("Simple IoT Vulnerability Scanner")
    ip = input("Enter the IP address to scan: ").strip()

    output = scan_ip(ip)
    if not output:
        return

    open_ports = get_open_ports(output)
    print("\nOpen Ports:", open_ports)

    issues = detect_anomalies(open_ports)
    if issues:
        print("\nSecurity Warnings:")
        for issue in issues:
            print("-", issue)
    else:
        print("\nNo major security issues detected.")

    risk = estimate_risk(issues)
    print(f"\nEstimated Risk Level: {risk}")

if __name__ == "__main__":
    main()
