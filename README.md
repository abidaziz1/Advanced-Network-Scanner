# Advanced Network Scanner with SYN Scanning and Vulnerability Detection
![Python](https://img.shields.io/badge/python-3.8-blue)
![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)
This tool is a Python-based network scanner that identifies active hosts, scans for open ports using stealthy SYN scans, detects services and operating systems, performs banner grabbing, and checks for potential vulnerabilities. It also includes functionality to save scan results in both JSON and CSV formats for further analysis.

## Features

- **Host Discovery**: Identifies active hosts on the network using a ping sweep.
- **Stealth SYN Scan**: Performs a stealthy port scan using SYN packets to detect open ports without completing a full TCP handshake.
- **Service and OS Detection**: Leverages `nmap` to identify running services, their versions, and the operating system.
- **Banner Grabbing**: Extracts banners from open ports to identify services.
- **Vulnerability Detection**: Simple vulnerability assessment based on open ports and common weaknesses.
- **Output Formats**: Saves results to both JSON and CSV files for easy access and review.
- **Multithreaded Scanning**: Scans all TCP ports (1-65535) in parallel for fast results.
## Use Cases

- **Penetration Testing:** Use this tool to detect open ports, identify services, and run vulnerability scans on a target network.
- **Ethical Hacking:** Identify potential security flaws in networks using SYN scanning and SSH brute-force techniques.
- **Vulnerability Scanning:** Detect vulnerable services and operating systems by scanning all open ports.
- **Network Security Audits:** Perform comprehensive network scans to audit your organization's network security posture.


## Prerequisites

Ensure the following Python libraries are installed:

- `scapy`: For network packet manipulation and stealth scanning.
- `paramiko`: For handling SSH connections.
- `nmap`: For OS and service detection.
- `ipaddress`: For handling IP address ranges.

You can install these dependencies by running:

```bash
pip install scapy paramiko nmap ipaddress
```
## Usage

1. **Clone the Repository:** Clone the repository to your local system:
    ```bash
    git clone https://github.com/your-username/network-scanner.git
    cd network-scanner
    ```

2. **Run the Script:** Start the scanner by running the `network_scanner.py` script:
    ```bash
    python network_scanner.py
    ```

3. **Input Network Range:** When prompted, input the network range you wish to scan in CIDR notation. For example:
    ```text
    Enter network range (e.g., 192.168.1.0/24): 192.168.1.0/24
    ```

4. **View Results:** After the scan is complete, the results will be saved in two files:
    - **JSON Output:** `scan_results.json`
    - **CSV Output:** `scan_results.csv`

The results contain details about the hosts, open ports, OS and service information, vulnerability assessment, and service banners.

## Example Output

**Console Output:**
```text
Host 192.168.1.1 is active
Scanning open ports on 192.168.1.1 using SYN scan
Port 22 is open on 192.168.1.1 (SYN scan)
Running OS and service detection on 192.168.1.1
OS: Linux, Version: 2.6.X
Host 192.168.1.1 has SSH open. Attempting brute-force attack...
Trying root:123456
Success! Username: root Password: 123456 on 192.168.1.1
```
## Usage

1. **Clone the Repository:** Clone the repository to your local system:
    ```bash
    git clone https://github.com/your-username/network-scanner.git
    cd network-scanner
    ```

2. **Run the Script:** Start the scanner by running the `network_scanner.py` script:
    ```bash
    python network_scanner.py
    ```

3. **Input Network Range:** When prompted, input the network range you wish to scan in CIDR notation. For example:
    ```text
    Enter network range (e.g., 192.168.1.0/24): 192.168.1.0/24
    ```

4. **View Results:** After the scan is complete, the results will be saved in two files:
    - **JSON Output:** `scan_results.json`
    - **CSV Output:** `scan_results.csv`

The results contain details about the hosts, open ports, OS and service information, vulnerability assessment, and service banners.
## CSV Output (Sample - scan_results.csv):

| Host        | Open Ports | OS     | Version | Vulnerabilities                                     | Banners                                                |
|-------------|------------|--------|---------|-----------------------------------------------------|--------------------------------------------------------|
| 192.168.1.1 | [22, 80]   | Linux  | 2.6.X   | SSH Brute Force Attempt: Username: root, Password: 123456 | {22: SSH-2.0-OpenSSH_7.4, 80: Apache/2.4.18 (Ubuntu)}  |
## Limitations

- **Stealth Scan:** While SYN scanning is stealthier than a full TCP connection, it may still be detected by modern firewalls and Intrusion Detection Systems (IDS).
- **Wordlists for SSH Brute Force:** The SSH brute-force functionality requires user-provided wordlists (`userlist.txt` and `passlist.txt`). Larger wordlists will increase the time required for the brute-force attempt.
- **Vulnerability Detection:** The vulnerability detection in this script is simple and based on known open ports. It can be extended to include specific vulnerability databases or scanners.

## License

This project is licensed under the Apache License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and ethical testing purposes only. Do not use this tool on networks or systems that you do not have explicit permission to scan or attack. Unauthorized scanning and brute-forcing are illegal and punishable by law.

## Contributing

If you would like to contribute to the development of this tool, feel free to fork the repository, make your changes, and submit a pull request.

## Contact

For any questions or support, please open an issue in the repository or reach out via AzizAbid1@proton.me.

