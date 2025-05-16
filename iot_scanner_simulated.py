#!/usr/bin/env python3

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

def main():
    print("Simulated IoT Vulnerability Scanner (No Nmap Needed)")
    ip = input("Enter the device IP address: ").strip()
    ports_input = input(
        "Enter open ports separated by commas (e.g., 21,80,443): "
    ).strip()

    try:
        open_ports = []
        for p in ports_input.split(","):
            p = p.strip()
            if p.isdigit():
                open_ports.append(int(p))
    except Exception:
        print("Invalid input. Please enter numbers separated by commas.")
        return

    print(f"\nScanning {ip}...\n")
    print("Open Ports:", open_ports)

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
