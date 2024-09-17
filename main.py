import socket
import threading
from scapy.all import *
import nmap
import ipaddress
import os
import json
import csv

# Define Global Variables
open_ports = []
hosts = []
nm = nmap.PortScanner()
results = []

# Host Discovery (Ping Sweep)
def host_discovery(network):
    print(f"Scanning network: {network}")
    for ip in ipaddress.IPv4Network(network):
        try:
            if os.name == 'nt':
                response = os.system(f"ping -n 1 -w 1 {ip} > NUL")
            else:
                response = os.system(f"ping -c 1 -W 1 {ip} > /dev/null 2>&1")

            if response == 0:
                print(f"Host {ip} is active")
                hosts.append(str(ip))
        except Exception as e:
            print(f"Error scanning host {ip}: {e}")

# Stealth SYN Scan using Scapy
def stealth_scan(host, port):
    try:
        syn_packet = IP(dst=host) / TCP(dport=port, flags="S")
        syn_ack = sr1(syn_packet, timeout=1, verbose=False)
        if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == "SA":
            print(f"Port {port} is open on {host} (SYN scan)")
            open_ports.append(port)
    except Exception as e:
        print(f"Error in SYN scan on port {port}: {e}")

# Threaded Port Scan using SYN Scans
def threaded_stealth_scan(host):
    print(f"Scanning open ports on {host} using SYN scan")
    threads = []
    for port in range(1, 65535):
        t = threading.Thread(target=stealth_scan, args=(host, port))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

# OS and Service/Version Detection
def os_service_detection(host):
    print(f"Running OS and service detection on {host}")
    try:
        nm.scan(host, arguments='-O -sV')
        os_data = nm[host]['osclass'][0]['osfamily'] if 'osclass' in nm[host] else 'Unknown'
        version_data = nm[host]['osclass'][0]['osgen'] if 'osclass' in nm[host] else 'Unknown'
        print(f"OS: {os_data}, Version: {version_data}")
        return {"os": os_data, "version": version_data}
    except Exception as e:
        print(f"Error in OS/Service detection: {e}")
        return {"os": "Unknown", "version": "Unknown"}

# Banner Grabbing
def banner_grab(host, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((host, port))
        banner = s.recv(1024).decode().strip()
        print(f"Banner on port {port} of {host}: {banner}")
        s.close()
        return banner
    except Exception as e:
        print(f"Error grabbing banner on port {port} of {host}: {e}")
        return "No banner"

# Vulnerability Detection (Simple Version)
def vulnerability_scan(host):
    print(f"Running vulnerability scan on {host}")
    vulnerabilities = []
    for port in open_ports:
        if port == 22:
            vulnerabilities.append(f"Host {host} running SSH - Possible brute-force vulnerability")
        elif port == 80:
            vulnerabilities.append(f"Host {host} running HTTP - Ensure web application security")
    return vulnerabilities

# Save Results to JSON
def save_results_json(filename):
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Results saved to {filename} (JSON format)")
    except Exception as e:
        print(f"Error saving results to JSON: {e}")

# Save Results to CSV
def save_results_csv(filename):
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Host", "Open Ports", "OS", "Version", "Vulnerabilities", "Banners"])
            for result in results:
                writer.writerow([result['host'], result['open_ports'], result['os'], result['version'], result['vulnerabilities'], result['banners']])
        print(f"Results saved to {filename} (CSV format)")
    except Exception as e:
        print(f"Error saving results to CSV: {e}")

# Main Scanner
def network_scanner(network):
    # Step 1: Discover Hosts
    try:
        host_discovery(network)
    except ipaddress.AddressValueError:
        print(f"Invalid network range: {network}")
        return

    # Step 2: For Each Host, Run Port Scan, Service Detection, Banner Grabbing
    for host in hosts:
        open_ports.clear()
        threaded_stealth_scan(host)
        os_info = os_service_detection(host)
        vulnerabilities = vulnerability_scan(host)
        banners = {port: banner_grab(host, port) for port in open_ports}

        # Save Result for this Host
        results.append({
            "host": host,
            "open_ports": open_ports.copy(),
            "os": os_info['os'],
            "version": os_info['version'],
            "vulnerabilities": vulnerabilities,
            "banners": banners
        })

    # Save Results to Files
    save_results_json('scan_results.json')
    save_results_csv('scan_results.csv')

if __name__ == "__main__":
    network = input("Enter network range (e.g., 192.168.1.0/24): ")
    network_scanner(network)
