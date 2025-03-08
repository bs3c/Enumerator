#!/usr/bin/env python3

import subprocess
import sys
import re
from concurrent.futures import ThreadPoolExecutor

# ANSI colors for better output readability
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def print_status(message, status="info"):
    """Prints colored status messages."""
    color = {"info": GREEN, "warn": YELLOW, "error": RED}.get(status, RESET)
    print(f"{color}[+] {message}{RESET}")

def run_command(command, output_file):
    """Runs a system command, prints output in real-time, and writes it to a file."""
    print_status(f"Running: {command}")

    with open(output_file, "a") as f:
        f.write(f"\n[+] Running: {command}\n")

    try:
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line, end='')
            f.write(line)
        process.wait()
    except Exception as e:
        print_status(f"Error executing {command}: {e}", "error")

def check_and_install_tools():
    """Checks if required tools are installed, installs missing ones globally."""
    tools = {
        "nmap": "nmap",
        "whois": "whois",
        "theHarvester": "theharvester",
        "dig": "dnsutils",
        "nslookup": "dnsutils",
        "nikto": "nikto",
        "rpcinfo": "rpcbind",
        "snmpwalk": "snmp",
        "arp-scan": "arp-scan",
        "netdiscover": "netdiscover",
        "smbclient": "smbclient"
    }

    for tool, package in tools.items():
        if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            print_status(f"{tool} not found, installing...", "warn")
            subprocess.run(["sudo", "apt", "install", "-y", package], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                print_status(f"{tool} installed successfully.")
            else:
                print_status(f"Failed to install {tool}.", "error")
        else:
            print_status(f"{tool} is already installed.")

def is_valid_ip(ip):
    """Validates an IP address."""
    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    return re.match(pattern, ip) is not None

def is_valid_domain(domain):
    """Validates a domain name."""
    pattern = r"^(?!-)[A-Za-z0-9.-]{1,253}(?<!-)$"
    return re.match(pattern, domain) is not None if domain else True

def is_valid_protocol(protocol):
    """Validates protocol (http/https)."""
    return protocol in ["http", "https"]

def enumerate_linux(target_ip, domain, output_file, protocol):
    """Runs enumeration commands in parallel for efficiency."""
    print_status("Starting Linux enumeration...")

    commands = [
        f"nmap -T4 -p- --open {target_ip}",
        f"nmap -sC -sV {target_ip}",
        f"nmap -A -p- {target_ip}",
        f"nmap -sU --top-ports 100 {target_ip}",
        f"whois {domain if domain else target_ip}",
        f"dig any {domain if domain else target_ip} +noall +answer",
        f"nslookup {domain if domain else target_ip}",
        f"theHarvester -d {domain if domain else target_ip} -l 500 -b all",
        f"nikto -h {protocol}://{domain if domain else target_ip}",
        f"rpcinfo -p {target_ip}",
        f"snmpwalk -c public -v2c {target_ip}",
        f"arp-scan --localnet",
        f"netdiscover -r {target_ip}/24",
        f"smbclient -L //{target_ip} -N",
        f"showmount -e {target_ip}"
    ]

    # Run commands in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        for cmd in commands:
            executor.submit(run_command, cmd, output_file)

    print_status(f"Linux enumeration complete! Results saved to {output_file}")

def main():
    print_status("Checking for required tools...")
    check_and_install_tools()

    # Gather user input safely
    target_ip = input("Enter Target IP Address: ").strip()
    if not is_valid_ip(target_ip):
        print_status("Invalid IP address!", "error")
        sys.exit(1)

    domain = input("Enter Domain (leave blank if none): ").strip()
    if domain and not is_valid_domain(domain):
        print_status("Invalid domain!", "error")
        sys.exit(1)

    protocol = input("Enter Protocol (http/https): ").strip().lower()
    if not is_valid_protocol(protocol):
        print_status("Invalid protocol! Use 'http' or 'https'.", "error")
        sys.exit(1)

    output_file = input("Enter output filename (default: linux_enum_results.txt): ").strip() or "linux_enum_results.txt"

    enumerate_linux(target_ip, domain, output_file, protocol)

    print_status(f"All enumeration results saved in {output_file}")

if __name__ == "__main__":
    main()

