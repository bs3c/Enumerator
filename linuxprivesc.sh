#!/bin/bash

OUTPUT_FILE="linux_priv_esc_results.txt"

# Clear previous results
echo "[+] Checking privilege escalation possibilities..." | tee "$OUTPUT_FILE"
echo -e "\n==================== Linux Privilege Escalation Check ====================\n" > "$OUTPUT_FILE"

# **User & Group Information**
echo "[+] Checking current user and group information..."
echo -e "\n==================== User & Group Info ====================\n" | tee -a "$OUTPUT_FILE"
id | tee -a "$OUTPUT_FILE"

# **Sudo Permissions**
echo "[+] Checking sudo permissions..."
echo -e "\n==================== Sudo Permissions ====================\n" | tee -a "$OUTPUT_FILE"
sudo -l 2>/dev/null | tee -a "$OUTPUT_FILE"

# **Writable Files & Directories**
echo "[+] Checking for writable files and directories..."
echo -e "\n==================== Writable Files & Directories ====================\n" | tee -a "$OUTPUT_FILE"
find / -writable -type d 2>/dev/null | tee -a "$OUTPUT_FILE"

# **SUID & SGID Binaries**
echo "[+] Checking for SUID & SGID binaries..."
echo -e "\n==================== SUID & SGID Binaries ====================\n" | tee -a "$OUTPUT_FILE"
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null | tee -a "$OUTPUT_FILE"

# **Cron Jobs**
echo "[+] Checking for user cron jobs..."
echo -e "\n==================== Cron Jobs ====================\n" | tee -a "$OUTPUT_FILE"
crontab -l 2>/dev/null | tee -a "$OUTPUT_FILE"
echo -e "\n==================== System-wide Cron Jobs ====================\n" | tee -a "$OUTPUT_FILE"
ls -la /etc/cron* | tee -a "$OUTPUT_FILE"

# **Capabilities**
echo "[+] Checking capabilities of binaries..."
echo -e "\n==================== Capabilities ====================\n" | tee -a "$OUTPUT_FILE"
getcap -r / 2>/dev/null | tee -a "$OUTPUT_FILE"

# **NFS Shares (if applicable)**
echo "[+] Checking for NFS shares..."
echo -e "\n==================== NFS Shares ====================\n" | tee -a "$OUTPUT_FILE"
cat /etc/exports 2>/dev/null | tee -a "$OUTPUT_FILE"

# **PATH Misconfigurations**
echo "[+] Checking for dangerous PATH misconfigurations..."
echo -e "\n==================== PATH Misconfigurations ====================\n" | tee -a "$OUTPUT_FILE"
echo "$PATH" | tee -a "$OUTPUT_FILE"

# **Running Processes**
echo "[+] Checking running processes..."
echo -e "\n==================== Running Processes ====================\n" | tee -a "$OUTPUT_FILE"
ps aux | tee -a "$OUTPUT_FILE"

echo "[+] Checking processes running as root..."
echo -e "\n==================== Processes Running as Root ====================\n" | tee -a "$OUTPUT_FILE"
ps aux | grep "^root" | tee -a "$OUTPUT_FILE"

# **Environment Variables**
echo "[+] Checking environment variables..."
echo -e "\n==================== Environment Variables ====================\n" | tee -a "$OUTPUT_FILE"
env | tee -a "$OUTPUT_FILE"

# **Checking for sensitive files**
echo "[+] Checking for sensitive files..."
echo -e "\n==================== Sensitive Files ====================\n" | tee -a "$OUTPUT_FILE"
ls -la /root/ 2>/dev/null | tee -a "$OUTPUT_FILE"
ls -la ~/.ssh/ 2>/dev/null | tee -a "$OUTPUT_FILE"

# **Checking /etc/passwd for writable permissions**
echo "[+] Checking if /etc/passwd is writable..."
echo -e "\n==================== /etc/passwd Writable Check ====================\n" | tee -a "$OUTPUT_FILE"
ls -lah /etc/passwd | tee -a "$OUTPUT_FILE"

# **Checking for SSH keys**
echo "[+] Checking for SSH private keys..."
echo -e "\n==================== SSH Private Keys ====================\n" | tee -a "$OUTPUT_FILE"
find / -name "id_rsa" -type f 2>/dev/null | tee -a "$OUTPUT_FILE"

# **Checking for world-writable files owned by root**
echo "[+] Checking for world-writable files owned by root..."
echo -e "\n==================== World-Writable Root-Owned Files ====================\n" | tee -a "$OUTPUT_FILE"
find / -user root -perm -o+w -type f 2>/dev/null | tee -a "$OUTPUT_FILE"

# **Checking Docker & LXC Group Membership**
echo "[+] Checking if the user is in the Docker or LXC group..."
echo -e "\n==================== Docker & LXC Group Membership ====================\n" | tee -a "$OUTPUT_FILE"
groups | grep -E "docker|lxc" | tee -a "$OUTPUT_FILE"

# **Checking for Exposed Services Listening on High Ports**
echo "[+] Checking for exposed services on uncommon ports..."
echo -e "\n==================== High Port Services ====================\n" | tee -a "$OUTPUT_FILE"
nmap -sS -p 10000-65535 localhost 2>/dev/null | tee -a "$OUTPUT_FILE"

# **Checking sudo -l for potential privilege escalation**
echo "[+] Checking for exploitable sudo permissions..."
echo -e "\n==================== Sudo -l Check ====================\n" | tee -a "$OUTPUT_FILE"
sudo -l 2>/dev/null | tee -a "$OUTPUT_FILE"

# **Quick Privilege Escalation Tests**
echo "[+] Running quick privilege escalation tests..."
echo -e "\n==================== Quick Privilege Escalation Tests ====================\n" | tee -a "$OUTPUT_FILE"
/bin/bash -p 2>/dev/null | tee -a "$OUTPUT_FILE"
perl -e 'exec "/bin/sh";' 2>/dev/null | tee -a "$OUTPUT_FILE"
find / -user root -perm -4000 -exec /bin/bash -p \; 2>/dev/null | tee -a "$OUTPUT_FILE"

# **Complete**
echo "[+] Privilege escalation check completed. Results saved to: $OUTPUT_FILE"
