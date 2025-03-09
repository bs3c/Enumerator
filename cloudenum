#!/bin/bash

# Ensure required cloud tools are installed
REQUIRED_TOOLS=("awscli" "az" "gcloud" "s3scanner" "cloudbrute" "amass" "subfinder" "nuclei")

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo "[-] Error: $tool is not installed. Please install it before running install_tools.sh."
        exit 1
    fi
done

# Prompt for Cloud Provider
echo "[+] Choose Cloud Provider:"
echo "1) AWS"
echo "2) Azure"
echo "3) Google Cloud (GCP)"
echo "4) All"
read -p "[+] Enter choice (1-4): " CLOUD_PROVIDER

# Prompt for target organization/domain
read -p "[+] Enter target organization or primary domain (e.g., example.com): " PRIMARY_DOMAIN
read -p "[+] Enter additional domains (comma-separated, e.g., cloud.example.com,api.example.com) or press Enter to skip: " ADDITIONAL_DOMAINS
OUTPUT_FILE="cloud_enum_results.txt"

# Convert comma-separated domains into an array
IFS=',' read -r -a DOMAIN_LIST <<< "$ADDITIONAL_DOMAINS"

# Add domains to /etc/hosts
echo "[+] Adding $PRIMARY_DOMAIN and any additional domains to /etc/hosts..."
echo "127.0.0.1 $PRIMARY_DOMAIN" | sudo tee -a /etc/hosts > /dev/null
for DOMAIN in "${DOMAIN_LIST[@]}"; do
    echo "127.0.0.1 $DOMAIN" | sudo tee -a /etc/hosts > /dev/null
done

# Max concurrent scans
MAX_CONCURRENT_SCANS=5

# Clear previous results
echo "[+] Starting Cloud Enumeration for: $PRIMARY_DOMAIN" | tee "$OUTPUT_FILE"
echo "[+] Results will be saved in: $OUTPUT_FILE"
echo "[+] Limiting to $MAX_CONCURRENT_SCANS parallel scans..."
echo -e "\n==================== Cloud Enumeration Results ====================\n" > "$OUTPUT_FILE"

# Function to run scans in parallel
run_scan() {
    local scan="$1"
    local header="==================== $(echo "$scan" | cut -d' ' -f1-2) ===================="

    echo "[+] Running: $scan"
    echo -e "\n$header\n" | tee -a "$OUTPUT_FILE"

    eval "$scan" 2>&1 | tee -a "$OUTPUT_FILE"

    echo "[+] Finished: $scan"
}

# **AWS Enumeration**
if [[ "$CLOUD_PROVIDER" == "1" || "$CLOUD_PROVIDER" == "4" ]]; then
    AWS_SCANS=(
        "aws s3 ls"
        "aws iam list-users"
        "aws ec2 describe-instances"
        "aws lambda list-functions"
        "aws sts get-caller-identity"
        "s3scanner -i s3_buckets.txt -o s3_results.txt"
    )

    echo "[+] Running AWS Enumeration..."
    for scan in "${AWS_SCANS[@]}"; do
        run_scan "$scan" &
    done
fi

# **Azure Enumeration**
if [[ "$CLOUD_PROVIDER" == "2" || "$CLOUD_PROVIDER" == "4" ]]; then
    AZURE_SCANS=(
        "az account show"
        "az ad user list"
        "az storage account list"
        "az vm list"
        "az aks list"
    )

    echo "[+] Running Azure Enumeration..."
    for scan in "${AZURE_SCANS[@]}"; do
        run_scan "$scan" &
    done
fi

# **Google Cloud (GCP) Enumeration**
if [[ "$CLOUD_PROVIDER" == "3" || "$CLOUD_PROVIDER" == "4" ]]; then
    GCP_SCANS=(
        "gcloud projects list"
        "gcloud compute instances list"
        "gcloud iam service-accounts list"
        "gcloud storage buckets list"
    )

    echo "[+] Running GCP Enumeration..."
    for scan in "${GCP_SCANS[@]}"; do
        run_scan "$scan" &
    done
fi

# **Common Cloud Recon**
COMMON_SCANS=(
    "amass enum -passive -d $PRIMARY_DOMAIN"
    "subfinder -d $PRIMARY_DOMAIN"
    "cloudbrute -d $PRIMARY_DOMAIN -w /usr/share/seclists/Discovery/DNS/cloud_subdomains.txt"
    "nuclei -t cloud -target $PRIMARY_DOMAIN"
)

echo "[+] Running Common Cloud Recon..."
for scan in "${COMMON_SCANS[@]}"; do
    run_scan "$scan" &
done

# Wait for all scans to complete
wait

echo "[+] Cloud Enumeration Completed. Results saved to: $OUTPUT_FILE"

