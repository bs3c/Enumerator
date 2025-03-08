require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote
  include Msf::Auxiliary::Scanner  # Enables scanning multiple targets

  def initialize
    super(
      'Name'        => 'Enhanced Linux Enumeration Module',
      'Description' => 'Performs active enumeration on Linux targets, permanently adds domain to /etc/hosts, and runs searchsploit on discovered services.',
      'Author'      => ['YourName'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptAddressRange.new('RHOSTS', [true, 'Target IP address(es)']),
        OptString.new('DOMAIN', [false, 'Domain name (if applicable)']),
        OptEnum.new('PROTOCOL', [true, 'The protocol (http/https)', 'http', ['http', 'https']]),
        OptString.new('OUTPUT_FILE', [true, 'Output file', 'linux_enum_results.txt'])
      ]
    )
  end

  def add_to_hosts(ip, domain)
    """Adds target IP and domain to /etc/hosts permanently"""
    if domain && !domain.empty?
      print_status("Adding #{ip} #{domain} to /etc/hosts")
      `echo "#{ip} #{domain}" | sudo tee -a /etc/hosts > /dev/null`
    end
  end

  def run_command(command)
    print_status("Running: #{command}")
    output = `#{command} 2>/dev/null`
    print_good(output.chomp) unless output.empty?
    return output
  end

  def extract_versions(scan_output)
    """Extracts software versions from scan results"""
    versions = []
    scan_output.each_line do |line|
      if line =~ /(\w+)\s+(\d+\.\d+(\.\d+)?)/  # Example: Apache 2.4.29
        service, version = $1, $2
        versions << "#{service} #{version}"
      end
    end
    versions.uniq
  end

  def search_exploits(versions)
    """Runs searchsploit on detected software versions"""
    exploits = []
    versions.each do |service_version|
      print_status("Searching exploits for: #{service_version}")
      result = `searchsploit --color --nmap '#{service_version}'`
      exploits << result unless result.empty?
    end
    exploits
  end

  def run_host(ip)
    domain = datastore['DOMAIN']
    protocol = datastore['PROTOCOL']
    output_file = datastore['OUTPUT_FILE']

    add_to_hosts(ip, domain)  # Adds entry to /etc/hosts (Does not remove)

    print_status("Starting Linux enumeration on #{ip}...")

  commands = [
    "nmap -sC -sV #{ip}",
    "nmap -A -p- #{ip}",
    "nmap --script=vuln #{ip}",
    "nmap --script=http-enum,http-title,http-methods #{ip}",
    "nmap --script=smb-os-discovery,smb-enum*,smb-vuln* #{ip}",
    "nmap --script=snmp-info #{ip}",
    "arp-scan --localnet",
    "netdiscover -r #{ip}/24",
    "rpcinfo -p #{ip}",
    "snmpwalk -c public -v2c #{ip}",
    "whatweb #{protocol}://#{domain || ip}",
    "wappalyzer #{protocol}://#{domain || ip}",
    "dirsearch -u #{protocol}://#{domain || ip} -e php,html,txt,js,json",
    "feroxbuster -u #{protocol}://#{domain || ip} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "ffuf -u #{protocol}://#{domain || ip}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt",
    "subfinder -d #{domain}",
    "nikto -h #{protocol}://#{domain || ip}",
    "wpscan --url #{protocol}://#{domain || ip} --enumerate vp,ap,tt,u",
    "joomscan --url #{protocol}://#{domain || ip}",
    "nuclei -target #{protocol}://#{domain || ip}",
    "smbmap -H #{ip}",
    "enum4linux -a #{ip}",
    "smbclient -L //#{ip} -N",
    "showmount -e #{ip}",
    "ldapsearch -h #{ip} -x -s base namingcontexts",
    "nmap --script=mysql-info,mysql-databases,mysql-users,mysql-vuln-cve2016-6662 #{ip}",
    "nmap --script=ms-sql-info,ms-sql-config,ms-sql-empty-password,ms-sql-xp-cmdshell #{ip}",
    "nmap --script=pgsql-info #{ip}",
    "redis-cli -h #{ip} INFO",
    "aws s3 ls",
    "gcloud auth list",
    "kubectl get pods",
    "docker ps -a",
    "searchsploit $(cat #{output_file} | grep -Eo '[A-Za-z]+ [0-9]+\.[0-9]+(\.[0-9]+)?')"
  ]

    results = ""

    File.open(output_file, 'a') do |file|
      commands.each do |cmd|
        output = run_command(cmd)
        results << output

        # Write results to the output file
        file.puts(output)
      end
    end

    # Extract software versions & run searchsploit
    detected_versions = extract_versions(results)
    if detected_versions.any?
      print_status("Found software versions: #{detected_versions.join(', ')}")
      exploits = search_exploits(detected_versions)

      if exploits.any?
        File.open(output_file, 'a') do |file|
          file.puts("\n[+] Found potential exploits:\n")
          exploits.each { |e| file.puts(e) }
        end
        print_good("[+] Exploits found! Check #{output_file}")
      else
        print_status("No known exploits found for detected versions.")
      end
    else
      print_status("No software versions detected in scan results.")
    end

    # Store final results in Metasploit DB
    framework.db.report_note(
      host: ip,
      type: "linux_enum",
      data: File.read(output_file)
    )

    print_status("Linux enumeration for #{ip} complete! Results saved to #{output_file}.")
  end
end

    print_status("Linux enumeration for #{ip} complete! Results saved to #{output_file}.")
  end
end
