require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote
  include Msf::Auxiliary::Scanner  # Enables scanning multiple targets

  def initialize
    super(
      'Name'        => 'Web & Cloud Enumeration Module',
      'Description' => 'Performs active enumeration on web & cloud targets and permanently adds subdomains to /etc/hosts',
      'Author'      => ['YourName'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptAddressRange.new('RHOSTS', [true, 'Target IP address(es)']),
        OptString.new('DOMAIN', [false, 'Domain name (if applicable)']),
        OptEnum.new('PROTOCOL', [true, 'The protocol (http/https)', 'http', ['http', 'https']]),
        OptString.new('OUTPUT_FILE', [true, 'Output file', 'web_cloud_enum_results.txt'])
      ]
    )
  end

  def add_to_hosts(domain, subdomains)
    """Adds discovered subdomains to /etc/hosts permanently"""
    return if subdomains.empty? || domain.nil? || domain.empty?

    print_status("Adding #{subdomains.length} subdomains for #{domain} to /etc/hosts")
    File.open('/etc/hosts', 'a') do |hosts_file|
      subdomains.each do |subdomain|
        entry = "127.0.0.1 #{subdomain}"
        hosts_file.puts(entry)
      end
    end
  end

  def run_host(ip)
    domain = datastore['DOMAIN']
    protocol = datastore['PROTOCOL']
    output_file = datastore['OUTPUT_FILE']

    print_status("Starting Web & Cloud enumeration on #{ip}...")

    commands = [
      "wappalyzer #{protocol}://#{domain || ip}",
      "gau #{domain || ip}",
      "katana -u #{protocol}://#{domain || ip}",
      "ffuf -u #{protocol}://#{domain || ip}/FUZZ -w api-wordlist.txt",
      "feroxbuster -u #{protocol}://#{domain || ip} --depth 2 -o #{output_file}",
      "nuclei -t cves/ -l #{ip}",
      "jwt_tool -t #{protocol}://#{domain || ip}/api/token",
      "jwt-cracker #{protocol}://#{domain || ip}/api/token",
      "wpscan --url #{protocol}://#{domain || ip} --enumerate vp",
      "joomscan --url #{protocol}://#{domain || ip}",
      "wafw00f #{protocol}://#{domain || ip}",
      "cloud_enum -k #{ip} -l",
      "amass enum -passive -d #{domain} -o subdomains.txt",
      "ffuf -u #{protocol}://#{domain || ip}/ -H 'Host: FUZZ.#{domain}' -w subdomains.txt -o ffuf_subdomains.txt",
      "subjack -d #{domain} -v -o takeoverable_subdomains.txt",
      "getjs -u #{protocol}://#{domain || ip} -o js_files.txt",
      "linkfinder -i #{protocol}://#{domain || ip} -o linkfinder_results.txt",
      "s3scanner #{ip}",
      "cloudbrute -d #{domain} -o cloudbrute_results.txt"
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
          type: "web_cloud_enum",
          data: result
        )
      end
    end

    # Add discovered subdomains to /etc/hosts
    subdomains = []
    if File.exist?('subdomains.txt')
      subdomains = File.readlines('subdomains.txt').map(&:strip)
      add_to_hosts(domain, subdomains)
    end

    print_status("Web & Cloud enumeration for #{ip} complete! Results saved to #{output_file}.")
  end
end

