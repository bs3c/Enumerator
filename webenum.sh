#!/bin/bash

# Ensure required tools are installed
REQUIRED_TOOLS=("amass" "subfinder" "ffuf" "feroxbuster" "whatweb" "nuclei" "nikto")
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo "[-] Error: $tool is not installed. Please install it before running install_tools.sh."
        exit 1
    fi
done

# Set target and prompt for domain
read -p "[+] Enter target IP or domain: " TARGET
read -p "[+] Enter main domain (e.g., example.com): " DOMAIN
read -p "[+] Is the target using HTTP or HTTPS? (http/https): " PROTOCOL
OUTPUT_FILE="web_enum_results.txt"

# Ensure valid protocol
if [[ "$PROTOCOL" != "http" && "$PROTOCOL" != "https" ]]; then
    echo "[-] Error: Invalid protocol. Use 'http' or 'https'."
    exit 1
fi

# Add domain to /etc/hosts
echo "[+] Adding $TARGET $DOMAIN to /etc/hosts..."
echo "$TARGET $DOMAIN" | sudo tee -a /etc/hosts > /dev/null

# Max concurrent processes
MAX_CONCURRENT_SCANS=5

# Clear previous results
echo "[+] Starting Web Enumeration for: $DOMAIN ($PROTOCOL)" | tee "$OUTPUT_FILE"
echo "[+] Results will be saved in: $OUTPUT_FILE"
echo "[+] Limiting to $MAX_CONCURRENT_SCANS parallel scans..."
echo -e "\n==================== Web Enumeration Results ====================\n" > "$OUTPUT_FILE"

# Define web enumeration commands
SCANS=(
    "feroxbuster -u $PROTOCOL://$DOMAIN -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -q"
    "ffuf -u $PROTOCOL://$DOMAIN/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt"
    "amass enum -passive -d $DOMAIN | tee -a subdomains.txt"
    "subfinder -d $DOMAIN -silent | tee -a subdomains.txt"
    "whatweb $PROTOCOL://$DOMAIN"
    "nikto -h $PROTOCOL://$DOMAIN"
    "nuclei -target $PROTOCOL://$DOMAIN"
)

# Function to run scans in parallel and append results
run_scan() {
    local scan="$1"
    local header="==================== $(echo "$scan" | cut -d' ' -f1-2) ===================="

    echo "[+] Running: $scan"
    echo -e "\n$header\n" | tee -a "$OUTPUT_FILE"

    # Run scan and output to both terminal and file
    eval "$scan" 2>&1 | tee -a "$OUTPUT_FILE"

    echo "[+] Finished: $scan"
}

# Start scans with controlled concurrency
ACTIVE_SCANS=()
for scan in "${SCANS[@]}"; do
    run_scan "$scan" &  # Run in the background
    ACTIVE_SCANS+=($!)  # Store PID

    # Limit concurrent scans
    while [ "$(jobs -r | wc -l)" -ge "$MAX_CONCURRENT_SCANS" ]; do
        sleep 2
    done
done

# Wait for all scans to complete
wait

# Process found subdomains and add them to /etc/hosts
if [ -f "subdomains.txt" ]; then
    echo "[+] Found subdomains:"
    cat subdomains.txt | tee -a "$OUTPUT_FILE"

    while IFS= read -r sub; do
        echo "$TARGET $sub" | sudo tee -a /etc/hosts > /dev/null
    done < subdomains.txt

    rm -f subdomains.txt
fi

echo "[+] Web Enumeration Completed. Results saved to: $OUTPUT_FILE"
