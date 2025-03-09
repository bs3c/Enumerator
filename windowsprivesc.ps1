# Windows Privilege Escalation Check Script

$OutputFile = "windows_priv_esc_results.txt"

# Clear previous results
"[+] Checking privilege escalation possibilities..." | Out-File -FilePath $OutputFile
"`n==================== Windows Privilege Escalation Check ====================`n" | Out-File -Append -FilePath $OutputFile

# **User & Group Information**
"[+] Checking current user and group information..." | Out-File -Append -FilePath $OutputFile
"`n==================== User & Group Info ====================`n" | Out-File -Append -FilePath $OutputFile
whoami /all | Out-File -Append -FilePath $OutputFile

# **Checking for Administrator Privileges**
"[+] Checking if the user has administrator privileges..." | Out-File -Append -FilePath $OutputFile
"`n==================== Administrator Check ====================`n" | Out-File -Append -FilePath $OutputFile
whoami /priv | Out-File -Append -FilePath $OutputFile

# **Checking for Writable Directories**
"[+] Checking for writable directories..." | Out-File -Append -FilePath $OutputFile
"`n==================== Writable Directories ====================`n" | Out-File -Append -FilePath $OutputFile
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.Attributes -match "Writable"} | Out-File -Append -FilePath $OutputFile

# **Checking for Scheduled Tasks**
"[+] Checking for scheduled tasks..." | Out-File -Append -FilePath $OutputFile
"`n==================== Scheduled Tasks ====================`n" | Out-File -Append -FilePath $OutputFile
schtasks /query /fo LIST /v | Out-File -Append -FilePath $OutputFile

# **Checking Running Processes**
"[+] Checking running processes..." | Out-File -Append -FilePath $OutputFile
"`n==================== Running Processes ====================`n" | Out-File -Append -FilePath $OutputFile
Get-Process | Out-File -Append -FilePath $OutputFile

# **Checking Running Processes as SYSTEM**
"[+] Checking processes running as SYSTEM..." | Out-File -Append -FilePath $OutputFile
"`n==================== Processes Running as SYSTEM ====================`n" | Out-File -Append -FilePath $OutputFile
Get-WmiObject Win32_Process | Where-Object { $_.GetOwner().User -eq "SYSTEM" } | Select-Object ProcessId, Name | Out-File -Append -FilePath $OutputFile

# **Checking for Stored Credentials**
"[+] Checking for stored credentials..." | Out-File -Append -FilePath $OutputFile
"`n==================== Stored Credentials ====================`n" | Out-File -Append -FilePath $OutputFile
cmdkey /list | Out-File -Append -FilePath $OutputFile

# **Checking for Firewall Rules**
"[+] Checking firewall rules..." | Out-File -Append -FilePath $OutputFile
"`n==================== Firewall Rules ====================`n" | Out-File -Append -FilePath $OutputFile
netsh advfirewall firewall show rule name=all | Out-File -Append -FilePath $OutputFile

# **Checking Installed Software**
"[+] Checking installed software..." | Out-File -Append -FilePath $OutputFile
"`n==================== Installed Software ====================`n" | Out-File -Append -FilePath $OutputFile
Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Out-File -Append -FilePath $OutputFile

# **Checking for Open Ports**
"[+] Checking open ports..." | Out-File -Append -FilePath $OutputFile
"`n==================== Open Ports ====================`n" | Out-File -Append -FilePath $OutputFile
netstat -ano | Out-File -Append -FilePath $OutputFile

# **Checking for Unquoted Service Paths**
"[+] Checking for unquoted service paths..." | Out-File -Append -FilePath $OutputFile
"`n==================== Unquoted Service Paths ====================`n" | Out-File -Append -FilePath $OutputFile
Get-WmiObject Win32_Service | Where-Object { $_.PathName -match '"' -eq $false } | Select-Object Name, PathName | Out-File -Append -FilePath $OutputFile

# **Checking for Weak Permissions on Services**
"[+] Checking for weak service permissions..." | Out-File -Append -FilePath $OutputFile
"`n==================== Weak Service Permissions ====================`n" | Out-File -Append -FilePath $OutputFile
Get-WmiObject Win32_Service | Select-Object Name, StartName | Out-File -Append -FilePath $OutputFile

# **Checking User's Token Privileges**
"[+] Checking user's token privileges..." | Out-File -Append -FilePath $OutputFile
"`n==================== User Token Privileges ====================`n" | Out-File -Append -FilePath $OutputFile
whoami /priv | Out-File -Append -FilePath $OutputFile

# **Checking for Network Shares**
"[+] Checking for accessible network shares..." | Out-File -Append -FilePath $OutputFile
"`n==================== Network Shares ====================`n" | Out-File -Append -FilePath $OutputFile
net view /all | Out-File -Append -FilePath $OutputFile

# **Complete**
"[+] Privilege escalation check completed. Results saved to: $OutputFile" | Out-File -Append -FilePath $OutputFile
