#!/bin/bash

# Set target and output file
TARGET="$1"
OUTPUT_FILE="${2:-nmap_results.txt}"  # Default output file if not specified
MAX_CONCURRENT_SCANS=5  # Limit parallel scans to avoid system overload

# Ensure a target is provided
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip_or_domain> [output_file]"
    exit 1
fi

# Clear previous results
echo "[+] Starting Nmap enumeration for: $TARGET" | tee "$OUTPUT_FILE"
echo "[+] Results will be saved in: $OUTPUT_FILE"
echo "[+] Limiting to $MAX_CONCURRENT_SCANS parallel scans..."
echo -e "\n==================== Nmap Scan Results ====================\n" > "$OUTPUT_FILE"

# Define Nmap scans
SCANS=(
    "nmap $TARGET"
    "nmap -sC -sV -p- $TARGET"
    "nmap --script=smb-os-discovery,smb-enum-shares,smb-enum-users,smb-vuln* -p 445 $TARGET"
    "nmap --script=snmp-info,snmp-sysdescr,snmp-netstat,snmp-processes -p 161 $TARGET"
    "nmap --script=http-title,http-enum,http-methods,http-robots.txt,http-server-header -p 80,443,8080 $TARGET"
    "nmap --script=ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor -p 21 $TARGET"
    "nmap --script=rdp-enum-encryption,rdp-vuln-ms12-020 -p 3389 $TARGET"
    "nmap --script=mysql-info,mysql-databases,mysql-users,mysql-vuln-cve2016-6662 -p 3306 $TARGET"
    "nmap --script=ms-sql-info,ms-sql-databases,ms-sql-empty-password -p 1433 $TARGET"
    "nmap --script=pgsql-info -p 5432 $TARGET"
    "nmap --script=nfs-ls,nfs-showmount,nfs-statfs -p 2049 $TARGET"
    "nmap --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p 22 $TARGET"
    "nmap --script=telnet-encryption,telnet-brute -p 23 $TARGET"
    "nmap --script=ldap-rootdse,ldap-search -p 389,636 $TARGET"
    "nmap --script=vuln -p- $TARGET"
)

# Function to run scans in parallel, print results as they finish, and save to file
run_scan() {
    local scan="$1"
    local header="==================== $(echo "$scan" | cut -d' ' -f2-) ===================="

    echo "[+] Running: $scan"
    echo -e "\n$header\n" | tee -a "$OUTPUT_FILE"

    # Run scan and output to both terminal and file in real-time
    eval "$scan" 2>&1 | tee -a "$OUTPUT_FILE"

    echo "[+] Finished: $scan"
}

# Start scans with controlled concurrency
ACTIVE_SCANS=()
for scan in "${SCANS[@]}"; do
    run_scan "$scan" &  # Run in the background
    ACTIVE_SCANS+=($!)  # Store PID

    # Limit concurrent scans to avoid overloading the system
    while [ "$(jobs -r | wc -l)" -ge "$MAX_CONCURRENT_SCANS" ]; do
        sleep 2
    done
done

# Wait for all scans to complete
wait

echo "[+] All scans completed. Results saved to: $OUTPUT_FILE"

