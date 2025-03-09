import os
import subprocess
import re
import argparse

def run_command(command):
    """Runs a shell command and returns the output."""
    print(f"[+] Running: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    output = result.stdout.strip()
    if output:
        print(output)
    return output

def add_to_hosts(ip, domain):
    """Permanently adds target IP and domain to /etc/hosts."""
    if domain:
        print(f"[+] Adding {ip} {domain} to /etc/hosts")
        os.system(f'echo "{ip} {domain}" | sudo tee -a /etc/hosts > /dev/null')

def extract_versions(scan_output):
    """Extracts software versions from scan results."""
    versions = []
    for line in scan_output.splitlines():
        match = re.search(r'(\w+)\s+(\d+\.\d+(\.\d+)?)', line)  # Example: Apache 2.4.29
        if match:
            service, version = match.group(1), match.group(2)
            versions.append(f"{service} {version}")
    return list(set(versions))  # Remove duplicates

def search_exploits(versions):
    """Runs searchsploit on detected software versions."""
    exploits = []
    for service_version in versions:
        print(f"[+] Searching exploits for: {service_version}")
        result = run_command(f"searchsploit --color --nmap '{service_version}'")
        if result:
            exploits.append(result)
    return exploits

def run_enumeration(ip, domain, protocol, output_file):
    """Runs enumeration commands and stores results."""
    if domain:
        add_to_hosts(ip, domain)

    commands = [
        f"nmap -sC -sV {ip}",
        f"nmap -A -p- {ip}",
        f"nmap --script=vuln {ip}",
        f"nmap --script=http-enum,http-title,http-methods {ip}",
        f"nmap --script=smb-os-discovery,smb-enum*,smb-vuln* {ip}",
        f"nmap --script=snmp-info {ip}",
        "arp-scan --localnet",
        f"netdiscover -r {ip}/24",
        f"rpcinfo -p {ip}",
        f"snmpwalk -c public -v2c {ip}",
        f"whatweb {protocol}://{domain or ip}",
        f"wappalyzer {protocol}://{domain or ip}",
        f"dirsearch -u {protocol}://{domain or ip} -e php,html,txt,js,json",
        f"feroxbuster -u {protocol}://{domain or ip} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        f"ffuf -u {protocol}://{domain or ip}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt",
        f"subfinder -d {domain}" if domain else "",
        f"nikto -h {protocol}://{domain or ip}",
        f"wpscan --url {protocol}://{domain or ip} --enumerate vp,ap,tt,u",
        f"joomscan --url {protocol}://{domain or ip}",
        f"nuclei -target {protocol}://{domain or ip}",
        f"smbmap -H {ip}",
        f"enum4linux -a {ip}",
        f"smbclient -L //{ip} -N",
        f"showmount -e {ip}",
        f"ldapsearch -h {ip} -x -s base namingcontexts",
        f"nmap --script=mysql-info,mysql-databases,mysql-users,mysql-vuln-cve2016-6662 {ip}",
        f"nmap --script=ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-xp-cmdshell {ip}",
        f"nmap --script=pgsql-info {ip}",
        f"redis-cli -h {ip} INFO",
        "aws s3 ls",
        "gcloud auth list",
        "kubectl get pods",
        "docker ps -a",
    ]

    results = ""
    with open(output_file, 'a') as file:
        for cmd in commands:
            if cmd:  # Skip empty commands
                output = run_command(cmd)
                results += output + "\n"
                file.write(output + "\n")

    # Extract software versions and search for exploits
    detected_versions = extract_versions(results)
    if detected_versions:
        print(f"[+] Found software versions: {', '.join(detected_versions)}")
        exploits = search_exploits(detected_versions)

        if exploits:
            with open(output_file, 'a') as file:
                file.write("\n[+] Found potential exploits:\n")
                file.writelines("\n".join(exploits))
            print(f"[+] Exploits found! Check {output_file}")
        else:
            print("[-] No known exploits found for detected versions.")
    else:
        print("[-] No software versions detected in scan results.")

    print(f"[+] Linux enumeration for {ip} complete! Results saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enhanced Linux Enumeration Script\n"
                    "Performs active enumeration on Linux targets, permanently adds domain to /etc/hosts, "
                    "and searches for known exploits.\n\n"
                    "Examples:\n"
                    "  python3 linux_enum.py 192.168.1.100 --domain example.com --protocol https --output results.txt\n",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("rhosts", help="Target IP address (e.g., 192.168.1.100)")
    parser.add_argument("--domain", help="Domain name (if applicable, e.g., example.com)", default="")
    parser.add_argument("--protocol", choices=["http", "https"], default="http",
                        help="Protocol (default: http, options: http, https)")
    parser.add_argument("--output", default="linux_enum_results.txt",
                        help="Output file for storing results (default: linux_enum_results.txt)")

    args = parser.parse_args()
    run_enumeration(args.rhosts, args.domain, args.protocol, args.output)
