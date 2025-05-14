

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
    if any("Telnet" in issue or "UPnP" in issue for issue in issues):
        return "High"
    elif issues:
        return "Medium"
    else:
        return "Low"

def main():
    print("Simulated IoT Vulnerability Scanner (No Nmap Needed)")
    ip = input("Enter the device IP address: ").strip()
    ports_input = input("Enter open ports separated by commas (e.g., 21,80,443): ").strip()

    try:
        open_ports = [int(p.strip()) for p in ports_input.split(",") if p.strip().isdigit()]
    except ValueError:
        print("Invalid input. Please enter numbers separated by commas.")
        return

    print(f"\nScanning {ip}...")

    print(f"\nOpen Ports: {open_ports}")
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
