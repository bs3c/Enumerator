# 🔥 Adding the Module to Metasploit

This guide walks you through the steps to **add, load, and run** the module's inside Metasploit.

---

## **📂 Step 1: Move the Module to Metasploit**
1. Open a terminal and run:
   ```bash
   mkdir -p ~/.msf4/modules/auxiliary/scanner/
   mv module.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/discovery
   sudo chown root:root /usr/share/metasploit-framework/modules/auxiliary/scanner/linuxenum.rb
   sudo chmod 644 /usr/share/metasploit-framework/modules/auxiliary/scanner/linuxenum.rb
   loadpath /usr/share/metasploit-framework/modules/

   msfconsole
   reload_all
   search linuxenum




   

