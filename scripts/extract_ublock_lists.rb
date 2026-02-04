#!/usr/bin/env ruby
# frozen_string_literal: true

# uBlock Origin Filter List Extractor for Pi-hole
# This script downloads uBlock Origin's filter lists and converts them to Pi-hole format
#
# Usage:
#   ruby extract_ublock_lists.rb [--output-dir DIR] [--lists LIST1,LIST2]
#
# Examples:
#   ruby extract_ublock_lists.rb
#   ruby extract_ublock_lists.rb --output-dir /etc/pihole/custom
#   ruby extract_ublock_lists.rb --lists easylist,easyprivacy

require 'net/http'
require 'uri'
require 'optparse'
require 'fileutils'
require 'set'

# Default filter list sources
FILTER_LISTS = {
  'ublock-filters' => 'https://ublockorigin.github.io/uAssets/filters/filters.txt',
  'ublock-badware' => 'https://ublockorigin.github.io/uAssets/filters/badware.txt',
  'ublock-privacy' => 'https://ublockorigin.github.io/uAssets/filters/privacy.txt',
  'ublock-unbreak' => 'https://ublockorigin.github.io/uAssets/filters/unbreak.txt',
  'easylist' => 'https://ublockorigin.github.io/uAssets/thirdparties/easylist.txt',
  'easyprivacy' => 'https://ublockorigin.github.io/uAssets/thirdparties/easyprivacy.txt',
  'peter-lowe' => 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext',
  'urlhaus-malware' => 'https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-hosts.txt',
  # Additional popular lists
  'adguard-dns' => 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',
  'steven-black-hosts' => 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
  'energized-basic' => 'https://block.energized.pro/basic/formats/hosts.txt',
  'oisd-basic' => 'https://abp.oisd.nl/basic/',
}.freeze

class UBlockExtractor
  def initialize(output_dir:, lists: nil)
    @output_dir = output_dir
    @lists = lists || FILTER_LISTS.keys
    @blocklist_domains = Set.new
    @allowlist_domains = Set.new
  end

  def run
    puts "uBlock Origin Filter List Extractor for Pi-hole"
    puts "=" * 50
    puts

    FileUtils.mkdir_p(@output_dir)

    @lists.each do |list_name|
      url = FILTER_LISTS[list_name]
      if url.nil?
        puts "Warning: Unknown list '#{list_name}', skipping..."
        next
      end

      puts "Fetching: #{list_name}"
      content = fetch_url(url)

      if content
        blocked, allowed = parse_filter_list(content, list_name)
        @blocklist_domains.merge(blocked)
        @allowlist_domains.merge(allowed)
        puts "  -> Found #{blocked.size} blocked domains, #{allowed.size} allowed domains"
      else
        puts "  -> Failed to fetch"
      end
      puts
    end

    # Remove any domains that are in both lists (allowlist takes precedence)
    @blocklist_domains -= @allowlist_domains

    write_output_files
    print_summary
  end

  private

  def fetch_url(url)
    uri = URI.parse(url)
    response = Net::HTTP.get_response(uri)

    case response
    when Net::HTTPSuccess
      response.body
    when Net::HTTPRedirection
      fetch_url(response['location'])
    else
      nil
    end
  rescue StandardError => e
    puts "  Error fetching #{url}: #{e.message}"
    nil
  end

  def parse_filter_list(content, list_name)
    blocked = Set.new
    allowed = Set.new

    content.each_line do |line|
      line = line.strip

      # Skip comments and empty lines
      next if line.empty? || line.start_with?('#', '!', '[')

      # Handle hosts file format (0.0.0.0 domain or 127.0.0.1 domain)
      if line =~ /^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(.+)$/
        domain = $1.strip
        domain = domain.split('#').first.strip  # Remove inline comments
        blocked << domain if valid_domain?(domain)
        next
      end

      # Handle AdBlock/uBlock filter format
      if line.start_with?('||') && line.include?('^')
        # Block rule: ||domain.com^
        domain = line.gsub(/^\|\|/, '').gsub(/\^.*$/, '').strip
        blocked << domain if valid_domain?(domain)
      elsif line.start_with?('@@||') && line.include?('^')
        # Exception/allow rule: @@||domain.com^
        domain = line.gsub(/^@@\|\|/, '').gsub(/\^.*$/, '').strip
        allowed << domain if valid_domain?(domain)
      elsif line =~ /^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/
        # Plain domain format
        blocked << line if valid_domain?(line)
      end
    end

    [blocked, allowed]
  end

  def valid_domain?(domain)
    return false if domain.nil? || domain.empty?
    return false if domain.include?('*')  # Skip wildcards for now
    return false if domain.include?('/')  # Skip paths
    return false if domain.include?(':')  # Skip ports
    return false if domain == 'localhost'
    return false if domain =~ /^\d+\.\d+\.\d+\.\d+$/  # Skip IPs
    return false if domain.length > 253  # DNS limit

    # Basic domain validation
    domain =~ /^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/
  end

  def write_output_files
    # Write blocklist
    blocklist_path = File.join(@output_dir, 'blocklist.txt')
    File.open(blocklist_path, 'w') do |f|
      f.puts "# Pi-hole Blocklist - Generated from uBlock Origin filter lists"
      f.puts "# Generated: #{Time.now.utc.iso8601}"
      f.puts "# Total domains: #{@blocklist_domains.size}"
      f.puts "# Sources: #{@lists.join(', ')}"
      f.puts "#"
      f.puts "# Usage: Add this file URL to Pi-hole's adlist or copy domains to custom blocklist"
      f.puts
      @blocklist_domains.to_a.sort.each { |domain| f.puts domain }
    end

    # Write allowlist
    allowlist_path = File.join(@output_dir, 'allowlist.txt')
    File.open(allowlist_path, 'w') do |f|
      f.puts "# Pi-hole Allowlist - Exceptions from uBlock Origin filter lists"
      f.puts "# Generated: #{Time.now.utc.iso8601}"
      f.puts "# Total domains: #{@allowlist_domains.size}"
      f.puts "# Sources: #{@lists.join(', ')}"
      f.puts "#"
      f.puts "# Usage: Add these domains to Pi-hole's whitelist"
      f.puts
      @allowlist_domains.to_a.sort.each { |domain| f.puts domain }
    end

    # Write combined hosts file format (for direct use)
    hosts_path = File.join(@output_dir, 'hosts.txt')
    File.open(hosts_path, 'w') do |f|
      f.puts "# Pi-hole Hosts Format Blocklist"
      f.puts "# Generated: #{Time.now.utc.iso8601}"
      f.puts "# Total domains: #{@blocklist_domains.size}"
      f.puts
      @blocklist_domains.to_a.sort.each { |domain| f.puts "0.0.0.0 #{domain}" }
    end

    # Write list sources for reference
    sources_path = File.join(@output_dir, 'sources.txt')
    File.open(sources_path, 'w') do |f|
      f.puts "# Filter List Sources"
      f.puts "# These URLs can be added directly to Pi-hole if they support the format"
      f.puts
      @lists.each do |list_name|
        url = FILTER_LISTS[list_name]
        f.puts "# #{list_name}"
        f.puts url
        f.puts
      end
    end
  end

  def print_summary
    puts "=" * 50
    puts "Summary"
    puts "=" * 50
    puts "Total blocked domains: #{@blocklist_domains.size}"
    puts "Total allowed domains: #{@allowlist_domains.size}"
    puts
    puts "Output files:"
    puts "  #{File.join(@output_dir, 'blocklist.txt')} - Domain list for Pi-hole"
    puts "  #{File.join(@output_dir, 'allowlist.txt')} - Exception domains"
    puts "  #{File.join(@output_dir, 'hosts.txt')}     - Hosts file format"
    puts "  #{File.join(@output_dir, 'sources.txt')}   - Source URLs"
    puts
    puts "To use with Pi-hole:"
    puts "  1. Copy blocklist.txt contents to: pihole -b <domain>"
    puts "  2. Or add as URL to Group Management > Adlists"
    puts "  3. Add allowlist.txt domains to: pihole -w <domain>"
  end
end

# Parse command line options
options = {
  output_dir: File.join(Dir.pwd, 'blocklists', 'ublock'),
  lists: nil
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} [options]"

  opts.on('-o', '--output-dir DIR', 'Output directory for generated lists') do |dir|
    options[:output_dir] = dir
  end

  opts.on('-l', '--lists LIST1,LIST2', Array, 'Comma-separated list of filter lists to use') do |lists|
    options[:lists] = lists
  end

  opts.on('-a', '--available', 'Show available filter lists') do
    puts "Available filter lists:"
    FILTER_LISTS.each do |name, url|
      puts "  #{name}"
      puts "    #{url}"
    end
    exit
  end

  opts.on('-h', '--help', 'Show this help') do
    puts opts
    exit
  end
end.parse!

# Run the extractor
extractor = UBlockExtractor.new(
  output_dir: options[:output_dir],
  lists: options[:lists]
)
extractor.run
