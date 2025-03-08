require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote
  include Msf::Auxiliary::Scanner  # Enables scanning multiple targets

  def initialize
    super(
      'Name'        => 'Linux Enumeration Module',
      'Description' => 'Performs active enumeration on Linux targets and permanently adds domain to /etc/hosts',
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

  def run_host(ip)
    domain = datastore['DOMAIN']
    protocol = datastore['PROTOCOL']
    output_file = datastore['OUTPUT_FILE']

    add_to_hosts(ip, domain)  # Adds entry to /etc/hosts (Does not remove)

    print_status("Starting Linux enumeration on #{ip}...")

    commands = [
      "nmap -T4 -p- --open #{ip}",
      "nmap -sC -sV #{ip}",
      "nmap -A -p- #{ip}",
      "nmap -sU --top-ports 100 #{ip}",
      "whois #{domain || ip}",
      "dig any #{domain || ip} +noall +answer",
      "nslookup #{domain || ip}",
      "nikto -h #{protocol}://#{domain || ip}",
      "rpcinfo -p #{ip}",
      "snmpwalk -c public -v2c #{ip}",
      "arp-scan --localnet",
      "netdiscover -r #{ip}/24",
      "smbclient -L //#{ip} -N",
      "showmount -e #{ip}"
    ]

    File.open(output_file, 'a') do |file|
      commands.each do |cmd|
        print_status("Running: #{cmd}")

        IO.popen(cmd) do |io|
          io.each_line do |line|
            print_good(line.chomp)  # Print output as it runs
            file.puts(line.chomp)    # Write output to file
          end
        end

        # Store results in Metasploit DB after each command
        result = File.read(output_file)
        framework.db.report_note(
          host: ip,
          type: "linux_enum",
          data: result
        )
      end
    end

    print_status("Linux enumeration for #{ip} complete! Results saved to #{output_file}.")
  end
end
