#!/usr/bin/env python3

import os
import subprocess

def run_command(command, output_file):
    """Runs a system command, prints output in real-time, and writes it to a file."""
    with open(output_file, "a") as f:
        f.write(f"\n[+] Running: {command}\n")
    
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in process.stdout:
        print(line, end='')
        with open(output_file, "a") as f:
            f.write(line)
    process.wait()

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
            print(f"[!] {tool} not found, installing...")
            subprocess.run(f"sudo apt install -y {package}", shell=True)
            print(f"[+] {tool} installed successfully.")
        else:
            print(f"[+] {tool} is already installed.")

def enumerate_linux(target_ip, domain, output_file, protocol):
    print("[+] Running enumeration for Linux target...")
    run_command(f"nmap -T4 -p- --open {target_ip}", output_file)
    run_command(f"nmap -sC -sV {target_ip}", output_file)
    run_command(f"nmap -A -p- {target_ip}", output_file)
    run_command(f"nmap -sU --top-ports 100 {target_ip}", output_file)
    run_command(f"whois {domain if domain else target_ip}", output_file)
    run_command(f"dig any {domain if domain else target_ip} +noall +answer", output_file)
    run_command(f"nslookup {domain if domain else target_ip}", output_file)
    run_command(f"theHarvester -d {domain if domain else target_ip} -l 500 -b all", output_file)
    run_command(f"nikto -h {protocol}://{domain if domain else target_ip}", output_file)
    run_command(f"rpcinfo -p {target_ip}", output_file)
    run_command(f"snmpwalk -c public -v2c {target_ip}", output_file)
    run_command(f"arp-scan --localnet", output_file)
    run_command(f"netdiscover -r {target_ip}/24", output_file)
    run_command(f"smbclient -L //{target_ip} -N", output_file)
    run_command(f"showmount -e {target_ip}", output_file)
    print(f"[+] Linux enumeration complete! Results saved to {output_file}")

def main():
    print("[+] Checking for required tools...")
    check_and_install_tools()
    
    target_ip = input("Enter Target IP Address: ")
    domain = input("Enter Domain (leave blank if none): ") or None
    protocol = input("Enter Protocol (http/https): ").lower()
    output_file = input("Enter output filename (default: linux_enum_results.txt): ") or "linux_enum_results.txt"
    
    enumerate_linux(target_ip, domain, output_file, protocol)
    
    print(f"[+] All enumeration results saved in {output_file}")
    
if __name__ == "__main__":
    main()
