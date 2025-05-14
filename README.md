IoT-Vulnerability-Scanner

The proposed model is a lightweight CLI-based scanner designed to detect common vulnerabilities in IoT devices based on their open ports. The model uses a rule-based approach to flag insecure services such as Telnet, FTP, and UPnP, and evaluates the device's risk level using simple CVSS-like logic. Two versions of the scanner are provided: a real scanner that uses Nmap for active network scanning, and a simulated version that requires no setup and accepts manual input. This dual-mode design ensures the scanner is both realistic and portable, offering flexibility in educational or restricted environments.

- iot_scanner_final.py : Scans real devices (requires Nmap)
- iot_scanner_simulated.py : Simulated version (no Nmap required)
