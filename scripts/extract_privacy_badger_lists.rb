#!/usr/bin/env ruby
# frozen_string_literal: true

# Privacy Badger Filter List Extractor for Pi-hole
# This script downloads EFF's Privacy Badger seed data and converts it to Pi-hole format
#
# Data source: https://github.com/EFForg/privacybadger
#
# Privacy Badger classifies domains with three actions:
#   block       - Tracker that sets cookies across sites (fully blocked)
#   cookieblock - Tracker that can load but cookies stripped (partial block)
#   allow       - Not a tracker or DNT-compliant
#
# Usage:
#   ruby extract_privacy_badger_lists.rb [options]
#
# Examples:
#   ruby extract_privacy_badger_lists.rb
#   ruby extract_privacy_badger_lists.rb --output-dir /etc/pihole/custom
#   ruby extract_privacy_badger_lists.rb --include-cookieblock
#   ruby extract_privacy_badger_lists.rb --dnt-allowlist

require 'net/http'
require 'uri'
require 'json'
require 'optparse'
require 'fileutils'
require 'set'
require_relative 'blocklist_project_filter'

DATA_SOURCES = {
  'seed' => 'https://raw.githubusercontent.com/EFForg/privacybadger/master/src/data/seed.json',
  'pbconfig' => 'https://www.eff.org/files/pbconfig.json',
}.freeze

class PrivacyBadgerExtractor
  REPO_ROOT = File.expand_path('..', __dir__).freeze

  def initialize(output_dir:, include_cookieblock: false, dnt_allowlist: false)
    @output_dir = output_dir
    @include_cookieblock = include_cookieblock
    @dnt_allowlist = dnt_allowlist

    @blocked_domains = Set.new
    @cookieblock_domains = Set.new
    @allowed_domains = Set.new
    @dnt_domains = Set.new
    @yellowlist_domains = Set.new
    @repo_allowlists = Set.new
  end

  def run
    puts "Privacy Badger Filter List Extractor for Pi-hole"
    puts "=" * 50
    puts

    FileUtils.mkdir_p(@output_dir)

    fetch_seed_data
    fetch_pbconfig_data

    # Strip adult/gambling/fraud/malware/phishing/piracy/scam/drugs/ads domains
    # from the allowlist output only — operate on copies so blocklist building
    # continues to use the original yellowlist/DNT sets unchanged.
    blp_blocked = load_blocklist_project_domains
    @yellowlist_for_allowlist = @yellowlist_domains - blp_blocked
    @dnt_for_allowlist        = @dnt_domains        - blp_blocked
    removed = (@yellowlist_domains - @yellowlist_for_allowlist) |
              (@dnt_domains        - @dnt_for_allowlist)
    if removed.any?
      puts "Blocklist Project filter: removed #{removed.size} domain(s) from allowlist:"
      removed.to_a.sort.each { |d| puts "  - #{d}" }
    else
      puts "Blocklist Project filter: no domains removed from allowlist"
    end
    puts

    # Load repo manual allowlists so build_final_blocklist can exclude them
    # (e.g. medium.com, ocsp.comodoca.com — legitimate domains that Privacy Badger may block)
    @repo_allowlists = load_repo_allowlists(REPO_ROOT)
    repo_removed = @blocked_domains & @repo_allowlists
    repo_removed.merge(@cookieblock_domains & @repo_allowlists)
    if repo_removed.any?
      puts "Repo allowlist filter: removed #{repo_removed.size} domain(s) from blocklist:"
      repo_removed.to_a.sort.each { |d| puts "  - #{d}" }
    else
      puts "Repo allowlist filter: no domains removed from blocklist"
    end
    puts

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
      puts "  HTTP #{response.code}: #{url}"
      nil
    end
  rescue StandardError => e
    puts "  Error fetching #{url}: #{e.message}"
    nil
  end

  def fetch_seed_data
    puts "Fetching seed.json (Privacy Badger tracker database)..."
    content = fetch_url(DATA_SOURCES['seed'])

    unless content
      puts "  -> Failed to fetch seed data"
      return
    end

    data = JSON.parse(content)
    action_map = data['action_map'] || {}

    action_map.each do |domain, info|
      next unless valid_domain?(domain)

      heuristic = info['heuristic_action'] || info['heuristicAction'] || ''
      dnt = info['dnt'] == true

      @dnt_domains << domain if dnt

      case heuristic
      when 'block'
        @blocked_domains << domain
      when 'cookieblock'
        @cookieblock_domains << domain
      when 'allow', ''
        @allowed_domains << domain
      end
    end

    puts "  -> #{@blocked_domains.size} block, #{@cookieblock_domains.size} cookieblock, " \
         "#{@allowed_domains.size} allow, #{@dnt_domains.size} DNT-compliant"
    puts
  end

  def fetch_pbconfig_data
    puts "Fetching pbconfig.json (yellowlist / DNT policy)..."
    content = fetch_url(DATA_SOURCES['pbconfig'])

    unless content
      puts "  -> Failed to fetch pbconfig (non-fatal, continuing without yellowlist)"
      puts
      return
    end

    data = JSON.parse(content)

    # Yellowlist: domains allowed to set cookies even if they track (e.g. login providers)
    yellowlist = data['yellowlist'] || []
    yellowlist.each do |domain|
      @yellowlist_domains << domain if valid_domain?(domain)
    end

    puts "  -> #{@yellowlist_domains.size} yellowlisted domains"
    puts
  rescue JSON::ParserError => e
    puts "  -> Failed to parse pbconfig: #{e.message}"
    puts
  end

  def build_final_blocklist
    blocklist = @blocked_domains.dup
    blocklist.merge(@cookieblock_domains) if @include_cookieblock

    # Yellowlisted domains should not be blocked (they're permitted trackers)
    blocklist -= @yellowlist_domains

    # DNT-compliant domains: optionally move to allowlist
    blocklist -= @dnt_domains if @dnt_allowlist

    # Repo manual allowlists take precedence over any Privacy Badger block rule
    blocklist -= @repo_allowlists

    blocklist
  end

  def build_final_allowlist
    allowlist = Set.new
    allowlist.merge(@dnt_for_allowlist) if @dnt_allowlist
    allowlist.merge(@yellowlist_for_allowlist)
    allowlist
  end

  def write_output_files
    blocklist = build_final_blocklist
    allowlist = build_final_allowlist

    options_note = []
    options_note << "cookieblock domains included" if @include_cookieblock
    options_note << "DNT-compliant domains in allowlist" if @dnt_allowlist
    options_note = options_note.empty? ? "default options" : options_note.join(", ")

    # Write blocklist in ABP format (||domain^)
    # Pi-hole FTL v5.21+ parses this natively via gravity and matches the domain
    # AND all its subdomains, giving better coverage than plain domain lists.
    blocklist_path = File.join(@output_dir, 'blocklist.txt')
    File.open(blocklist_path, 'w') do |f|
      f.puts "! Pi-hole Blocklist (ABP format) - Generated from Privacy Badger seed data"
      f.puts "! Generated: #{Time.now.utc.iso8601}"
      f.puts "! Source: #{DATA_SOURCES['seed']}"
      f.puts "! Options: #{options_note}"
      f.puts "! Total domains: #{blocklist.size}"
      f.puts "!"
      f.puts "! Includes: 'block' action domains (cross-site cookie trackers)"
      f.puts "! Includes: 'cookieblock' domains" if @include_cookieblock
      f.puts "! Format: ||domain^ blocks domain and all subdomains (ABP/uBlock syntax)"
      f.puts
      blocklist.to_a.sort.each { |domain| f.puts "||#{domain}^" }
    end

    # Write cookieblock list in ABP format — same rationale as blocklist
    cookieblock_path = File.join(@output_dir, 'cookieblock.txt')
    File.open(cookieblock_path, 'w') do |f|
      f.puts "! Pi-hole Cookieblock List (ABP format) - Domains Privacy Badger allows but strips cookies"
      f.puts "! Generated: #{Time.now.utc.iso8601}"
      f.puts "! Source: #{DATA_SOURCES['seed']}"
      f.puts "! Total domains: #{@cookieblock_domains.size}"
      f.puts "!"
      f.puts "! These domains can load resources but would have cookies stripped by Privacy Badger."
      f.puts "! Blocking them in Pi-hole is more aggressive than Privacy Badger's default."
      f.puts "! Format: ||domain^ blocks domain and all subdomains (ABP/uBlock syntax)"
      f.puts
      @cookieblock_domains.to_a.sort.each { |domain| f.puts "||#{domain}^" }
    end

    # Write allowlist as plain domains
    # Pi-hole allowlists do not support ABP @@|| syntax; plain domains required.
    allowlist_path = File.join(@output_dir, 'allowlist.txt')
    File.open(allowlist_path, 'w') do |f|
      f.puts "# Pi-hole Allowlist - Privacy Badger yellowlist + optional DNT domains"
      f.puts "# Generated: #{Time.now.utc.iso8601}"
      f.puts "# Sources: #{DATA_SOURCES.values.join(', ')}"
      f.puts "# Total domains: #{allowlist.size}"
      f.puts "#"
      f.puts "# Yellowlist: permitted trackers (e.g. login/payment providers)"
      f.puts "# DNT domains included" if @dnt_allowlist
      f.puts
      allowlist.to_a.sort.each { |domain| f.puts domain }
    end

    # Write hosts format (plain 0.0.0.0 prefix, for direct /etc/hosts use)
    hosts_path = File.join(@output_dir, 'hosts.txt')
    File.open(hosts_path, 'w') do |f|
      f.puts "# Pi-hole Hosts Format Blocklist - Privacy Badger"
      f.puts "# Generated: #{Time.now.utc.iso8601}"
      f.puts "# Total domains: #{blocklist.size}"
      f.puts
      blocklist.to_a.sort.each { |domain| f.puts "0.0.0.0 #{domain}" }
    end

    # Write sources reference
    sources_path = File.join(@output_dir, 'sources.txt')
    File.open(sources_path, 'w') do |f|
      f.puts "# Privacy Badger Data Sources"
      f.puts "#"
      f.puts "# Domain data sourced from EFF Privacy Badger"
      f.puts "# https://github.com/EFForg/privacybadger"
      f.puts "#"
      f.puts "# Privacy Badger is licensed under the GNU General Public License v3+"
      f.puts "# https://www.gnu.org/licenses/gpl-3.0.html"
      f.puts "#"
      f.puts "# This derived data is redistributed under the same GPLv3+ license."
      f.puts
      DATA_SOURCES.each do |name, url|
        f.puts "# #{name}"
        f.puts url
        f.puts
      end
    end
  end

  def print_summary
    blocklist = build_final_blocklist
    allowlist = build_final_allowlist

    puts "=" * 50
    puts "Summary"
    puts "=" * 50
    puts "Block action domains:       #{@blocked_domains.size}"
    puts "Cookieblock action domains: #{@cookieblock_domains.size}"
    puts "Allow action domains:       #{@allowed_domains.size}"
    puts "DNT-compliant domains:      #{@dnt_domains.size}"
    puts "Yellowlisted domains:       #{@yellowlist_domains.size}"
    puts
    puts "Final blocklist size:  #{blocklist.size}"
    puts "Final allowlist size:  #{allowlist.size}"
    puts
    puts "Output files:"
    puts "  #{File.join(@output_dir, 'blocklist.txt')}    - Domains to block in Pi-hole"
    puts "  #{File.join(@output_dir, 'cookieblock.txt')}  - Cookie-stripped tracker domains"
    puts "  #{File.join(@output_dir, 'allowlist.txt')}    - Domains to whitelist in Pi-hole"
    puts "  #{File.join(@output_dir, 'hosts.txt')}        - Hosts file format"
    puts "  #{File.join(@output_dir, 'sources.txt')}      - Source URLs"
    puts
    puts "To use with Pi-hole:"
    puts "  1. Add blocklist.txt URL to Group Management > Adlists"
    puts "  2. Run: pihole -w \$(cat allowlist.txt | grep -v '^#' | tr '\\n' ' ')"
    puts
    puts "Options to consider:"
    puts "  --include-cookieblock  Also block cookie-stripped tracker domains (~#{@cookieblock_domains.size} more)"
    puts "  --dnt-allowlist        Move DNT-compliant domains to allowlist (~#{@dnt_domains.size} domains)" unless @dnt_allowlist
  end

  def valid_domain?(domain)
    return false if domain.nil? || domain.empty?
    return false if domain.include?('*')
    return false if domain.include?('/')
    return false if domain.include?(':')
    return false if domain == 'localhost'
    return false if domain =~ /^\d+\.\d+\.\d+\.\d+$/
    return false if domain.length > 253

    tld = domain.split('.').last.downcase
    return false if ADULT_TLDS.include?(tld)
    return false if FILE_EXTENSION_TLDS.include?(tld)

    # Skip well-known legitimate domains (shared constants from blocklist_project_filter.rb)
    return false if skip_domain_static?(domain)

    domain =~ /^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/
  end
end

# Parse command line options
options = {
  output_dir: File.join(Dir.pwd, 'blocklists', 'privacy-badger'),
  include_cookieblock: false,
  dnt_allowlist: false,
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} [options]"
  opts.separator ""
  opts.separator "Privacy Badger classifies domains as:"
  opts.separator "  block       - Cross-site cookie trackers (always blocked)"
  opts.separator "  cookieblock - Trackers with cookies stripped (blocked with --include-cookieblock)"
  opts.separator "  allow       - Non-trackers or DNT-compliant"
  opts.separator ""

  opts.on('-o', '--output-dir DIR', 'Output directory for generated lists') do |dir|
    options[:output_dir] = dir
  end

  opts.on('-c', '--include-cookieblock',
          'Also block cookieblock domains (more aggressive, may break some sites)') do
    options[:include_cookieblock] = true
  end

  opts.on('-d', '--dnt-allowlist',
          'Add DNT-compliant domains to the allowlist') do
    options[:dnt_allowlist] = true
  end

  opts.on('-h', '--help', 'Show this help') do
    puts opts
    exit
  end
end.parse!

extractor = PrivacyBadgerExtractor.new(
  output_dir: options[:output_dir],
  include_cookieblock: options[:include_cookieblock],
  dnt_allowlist: options[:dnt_allowlist]
)
extractor.run
