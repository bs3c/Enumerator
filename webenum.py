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
        "wappalyzer": "wappalyzer",
        "gau": "gau",
        "katana": "katana",
        "ffuf": "ffuf",
        "feroxbuster": "feroxbuster",
        "nuclei": "nuclei",
        "jwt_tool": "jwt-tool",
        "jwt-cracker": "jwt-cracker",
        "wpscan": "wpscan",
        "joomscan": "joomscan",
        "wafw00f": "wafw00f",
        "cloud_enum": "cloud_enum",
        "amass": "amass",
        "subjack": "subjack",
        "getjs": "getjs",
        "linkfinder": "linkfinder",
        "s3scanner": "s3scanner",
        "cloudbrute": "cloudbrute"
    }
    
    for tool, package in tools.items():
        if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            print(f"[!] {tool} not found, installing...")
            subprocess.run(f"sudo apt install -y {package}", shell=True)
            print(f"[+] {tool} installed successfully.")
        else:
            print(f"[+] {tool} is already installed.")

def add_to_hosts(domain, subdomains):
    """Adds discovered subdomains to /etc/hosts."""
    with open("/etc/hosts", "a") as hosts_file:
        for subdomain in subdomains:
            entry = f"127.0.0.1 {subdomain}\n"
            hosts_file.write(entry)
    print(f"[+] Added {len(subdomains)} subdomains to /etc/hosts")

def enumerate_web_cloud(target_ip, domain, output_file, protocol):
    print("[+] Running web and cloud enumeration...")
    run_command(f"wappalyzer {protocol}://{domain if domain else target_ip}", output_file)
    run_command(f"gau {domain if domain else target_ip}", output_file)
    run_command(f"katana -u {protocol}://{domain if domain else target_ip}", output_file)
    run_command(f"ffuf -u {protocol}://{domain if domain else target_ip}/FUZZ -w api-wordlist.txt", output_file)
    run_command(f"feroxbuster -u {protocol}://{domain if domain else target_ip} --depth 2 -o {output_file}", output_file)
    run_command(f"nuclei -t cves/ -l {target_ip}", output_file)
    run_command(f"jwt_tool -t {protocol}://{domain if domain else target_ip}/api/token", output_file)
    run_command(f"jwt-cracker {protocol}://{domain if domain else target_ip}/api/token", output_file)
    run_command(f"wpscan --url {protocol}://{domain if domain else target_ip} --enumerate vp", output_file)
    run_command(f"joomscan --url {protocol}://{domain if domain else target_ip}", output_file)
    run_command(f"wafw00f {protocol}://{domain if domain else target_ip}", output_file)
    run_command(f"cloud_enum -k {target_ip} -l", output_file)
    
    print("[+] Discovering subdomains...")
    run_command(f"amass enum -passive -d {domain} -o subdomains.txt", output_file)
    run_command(f"ffuf -u {protocol}://{domain if domain else target_ip}/ -H 'Host: FUZZ.{domain}' -w subdomains.txt -o ffuf_subdomains.txt", output_file)
    run_command(f"subjack -d {domain} -v -o takeoverable_subdomains.txt", output_file)
    
    print("[+] Extracting JavaScript files...")
    run_command(f"getjs -u {protocol}://{domain if domain else target_ip} -o js_files.txt", output_file)
    run_command(f"linkfinder -i {protocol}://{domain if domain else target_ip} -o linkfinder_results.txt", output_file)
    
    print("[+] Checking cloud misconfigurations...")
    run_command(f"s3scanner {target_ip}", output_file)
    run_command(f"cloudbrute -d {domain} -o cloudbrute_results.txt", output_file)
    
    subdomains = []
    if os.path.exists("subdomains.txt"):
        with open("subdomains.txt", "r") as f:
            subdomains = [line.strip() for line in f.readlines()]
        add_to_hosts(domain, subdomains)
    
    print(f"[+] Web & Cloud enumeration complete! Results saved to {output_file}")

def main():
    print("[+] Checking for required tools...")
    check_and_install_tools()
    
    target_ip = input("Enter Target IP Address: ")
    domain = input("Enter Domain (leave blank if none): ") or None
    protocol = input("Enter Protocol (http/https): ").lower()
    output_file = input("Enter output filename (default: web_cloud_enum_results.txt): ") or "web_cloud_enum_results.txt"
    
    enumerate_web_cloud(target_ip, domain, output_file, protocol)
    
    print(f"[+] All enumeration results saved in {output_file}")
    
if __name__ == "__main__":
    main()
