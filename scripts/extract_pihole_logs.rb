#!/usr/bin/env ruby
# frozen_string_literal: true

# Pi-hole Query Log Extractor
# Connects to a Pi-hole instance and extracts unique blocked/allowed domains
# from the query log, grouped by device (client IP) and in aggregate.
#
# Usage:
#   ruby scripts/extract_pihole_logs.rb --ip 192.168.1.1 --api-token TOKEN
#   ruby scripts/extract_pihole_logs.rb --ip 192.168.1.1 --password PASS
#   ruby scripts/extract_pihole_logs.rb --ip 192.168.1.1 --api-token TOKEN --from 2024-01-01 --until 2024-02-01
#
# Output (written to query_logs/ by default, excluded from git):
#   query_logs/all_blocked.txt         - unique blocked domains across all devices
#   query_logs/all_allowed.txt         - unique allowed domains across all devices
#   query_logs/devices/<ip>/blocked.txt
#   query_logs/devices/<ip>/allowed.txt

require 'optparse'
require 'fileutils'
require 'set'
require 'time'
require 'net/http'
require 'pihole-api'

# Query statuses that represent a block action in Pi-hole FTL
BLOCKED_STATUSES = [
  1,  # gravity
  4,  # regex/wildcard
  5,  # exact blacklist
  6,  # gravity (CNAME)
  7,  # regex (CNAME)
  8,  # blacklist (CNAME)
].freeze

# Query statuses that represent a permitted request
ALLOWED_STATUSES = [
  2,  # forwarded to upstream
  3,  # answered from cache
].freeze

REPO_ROOT = File.expand_path('..', __dir__).freeze
DEFAULT_OUTPUT_DIR = File.join(REPO_ROOT, 'query_logs').freeze

class PiholeLogExtractor
  def initialize(host:, port:, password: nil, api_token: nil, from_time: nil, until_time: nil, output_dir: DEFAULT_OUTPUT_DIR)
    @host = host
    @port = port
    @password = password
    @api_token = api_token
    @from_time = from_time
    @until_time = until_time
    @output_dir = output_dir
  end

  def run
    puts "Pi-hole Query Log Extractor"
    puts "=" * 50
    puts "Host: #{@host}:#{@port}"
    puts "Time range: #{time_range_description}"
    puts "Output: #{@output_dir}"
    puts

    client = build_client

    verify_connection!(client)

    puts "Fetching queries..."
    queries = fetch_queries(client)
    puts "Retrieved #{queries.size} queries"
    puts

    blocked_by_device = Hash.new { |h, k| h[k] = Set.new }
    allowed_by_device = Hash.new { |h, k| h[k] = Set.new }
    all_blocked = Set.new
    all_allowed = Set.new

    queries.each do |query|
      _timestamp, _type, domain, client_ip, status = query
      next if domain.nil? || domain.empty?

      status = status.to_i

      if BLOCKED_STATUSES.include?(status)
        blocked_by_device[client_ip] << domain
        all_blocked << domain
      elsif ALLOWED_STATUSES.include?(status)
        allowed_by_device[client_ip] << domain
        all_allowed << domain
      end
    end

    write_output(all_blocked, all_allowed, blocked_by_device, allowed_by_device)
    print_summary(all_blocked, all_allowed, blocked_by_device, allowed_by_device)
  end

  private

  def build_client
    base_path = "http://#{@host}/"

    if @api_token
      # Pass empty string so the gem constructs without hashing, then inject the
      # pre-hashed token directly (avoids a second round of double-SHA256).
      client = PiholeApi::Client.new(base_path: base_path, password: '', port: @port)
      client.instance_variable_set(:@api_token, @api_token)
      client
    else
      PiholeApi::Client.new(base_path: base_path, password: @password, port: @port)
    end
  end

  def verify_connection!(client)
    print "Verifying connection and credentials... "
    response = client.summary
    body = response['body']

    case body
    when Hash
      # Pi-hole summary with correct auth returns keys like dns_queries_today,
      # domains_being_blocked, status, etc. An empty hash means auth failed.
      if body.empty?
        abort "\nError: Authentication failed — Pi-hole returned an empty summary.\n" \
              "Check your --api-token or --password."
      end
      puts "OK"
    when Array
      # Pi-hole returns "[]" (→ empty Array) on auth failure for many endpoints.
      if body.empty?
        abort "\nError: Authentication failed — Pi-hole returned an empty response.\n" \
              "Check your --api-token or --password."
      end
      puts "OK"
    when String
      abort "\nError: Pi-hole returned a non-JSON response. Check that #{@host}:#{@port} is " \
            "a Pi-hole instance with the API enabled.\nResponse preview: #{body[0..300]}"
    else
      abort "\nError: Unexpected response type #{body.class} from Pi-hole."
    end
  rescue SocketError, Errno::ECONNREFUSED, Errno::ETIMEDOUT, Net::OpenTimeout => e
    abort "\nError: Could not connect to #{@host}:#{@port} — #{e.message}"
  rescue StandardError => e
    abort "\nError connecting to Pi-hole: #{e.message}"
  end

  def fetch_queries(client)
    kwargs = {}
    kwargs[:from_time] = @from_time if @from_time
    kwargs[:until_time] = @until_time if @until_time

    response = client.get_all_queries(**kwargs)
    body = response['body']

    case body
    when Hash
      body['data'] || []
    when Array
      # Pi-hole sends the literal string "[]" (parsed by the gem to an empty Array)
      # specifically when authentication fails for getAllQueries. A successful call
      # with no results returns {"data": []} (a Hash), so an Array here is always
      # an auth error rather than a genuinely empty result set.
      abort "Error: Authentication failed for getAllQueries — Pi-hole returned an empty array.\n" \
            "Check your --api-token or --password."
    when String
      abort "Error: Pi-hole returned a non-JSON response for getAllQueries.\n" \
            "Check that #{@host}:#{@port} is a Pi-hole instance and the API is accessible.\n" \
            "Response preview: #{body[0..300]}"
    else
      abort "Error: Unexpected response type #{body.class} from Pi-hole API."
    end
  rescue StandardError => e
    abort "Error fetching queries from Pi-hole: #{e.message}"
  end

  def write_output(all_blocked, all_allowed, blocked_by_device, allowed_by_device)
    FileUtils.mkdir_p(@output_dir)

    write_list(File.join(@output_dir, 'all_blocked.txt'), all_blocked, 'Blocked domains (all devices)')
    write_list(File.join(@output_dir, 'all_allowed.txt'), all_allowed, 'Allowed domains (all devices)')

    all_devices = (blocked_by_device.keys + allowed_by_device.keys).uniq.sort
    all_devices.each do |device_ip|
      safe_name = device_ip.gsub(':', '-').gsub(%r{[/\\]}, '_')
      device_dir = File.join(@output_dir, 'devices', safe_name)
      FileUtils.mkdir_p(device_dir)

      write_list(File.join(device_dir, 'blocked.txt'), blocked_by_device[device_ip], "Blocked domains - #{device_ip}")
      write_list(File.join(device_dir, 'allowed.txt'), allowed_by_device[device_ip], "Allowed domains - #{device_ip}")
    end
  end

  def write_list(path, domains, title)
    File.open(path, 'w') do |f|
      f.puts "# #{title}"
      f.puts "# Generated: #{Time.now.utc.iso8601}"
      f.puts "# Total unique domains: #{domains.size}"
      f.puts "# Time range: #{time_range_description}" if @from_time || @until_time
      f.puts
      domains.to_a.sort.each { |d| f.puts d }
    end
    puts "  #{path} (#{domains.size} domains)"
  end

  def print_summary(all_blocked, all_allowed, blocked_by_device, allowed_by_device)
    device_count = (blocked_by_device.keys + allowed_by_device.keys).uniq.size

    puts
    puts "=" * 50
    puts "Summary"
    puts "=" * 50
    puts "Unique blocked domains : #{all_blocked.size}"
    puts "Unique allowed domains : #{all_allowed.size}"
    puts "Devices                : #{device_count}"
    puts
    puts "Output: #{@output_dir}"
  end

  def time_range_description
    from = @from_time ? @from_time.iso8601 : 'all time'
    to   = @until_time ? @until_time.iso8601 : 'now'
    @from_time || @until_time ? "#{from} → #{to}" : 'all time'
  end
end

def parse_time_arg(str)
  if str =~ /^\d+$/
    Time.at(str.to_i)
  else
    Time.parse(str)
  end
rescue ArgumentError => e
  abort "Invalid time '#{str}': #{e.message}"
end

options = {
  port: 80,
  output_dir: DEFAULT_OUTPUT_DIR,
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} --ip HOST (--api-token TOKEN | --password PASS) [options]"
  opts.separator ''
  opts.separator 'Connection (required):'

  opts.on('--ip HOST', 'Pi-hole IP address or hostname') do |v|
    options[:host] = v
  end

  opts.on('--port PORT', Integer, 'Pi-hole port (default: 80)') do |v|
    options[:port] = v
  end

  opts.separator ''
  opts.separator 'Authentication (one required):'

  opts.on('--api-token TOKEN',
          'Pre-hashed API token (shown in Pi-hole Settings > API/Web Interface)') do |v|
    options[:api_token] = v
  end

  opts.on('--password PASSWORD',
          'Plain admin password (hashed automatically by the client)') do |v|
    options[:password] = v
  end

  opts.separator ''
  opts.separator 'Time range (optional, default: all time):'

  opts.on('--from TIMESTAMP', 'Start time: unix timestamp or ISO8601 (e.g. 2024-01-01T00:00:00)') do |v|
    options[:from_time] = parse_time_arg(v)
  end

  opts.on('--until TIMESTAMP', 'End time: unix timestamp or ISO8601') do |v|
    options[:until_time] = parse_time_arg(v)
  end

  opts.separator ''
  opts.separator 'Output:'

  opts.on('-o', '--output-dir DIR', "Output directory (default: query_logs/ at repo root)") do |v|
    options[:output_dir] = File.expand_path(v)
  end

  opts.separator ''
  opts.on('-h', '--help', 'Show this help') { puts opts; exit }
end.parse!

abort "Error: --ip is required. Run with --help for usage." unless options[:host]
abort "Error: --api-token or --password is required. Run with --help for usage." unless options[:api_token] || options[:password]

PiholeLogExtractor.new(
  host:       options[:host],
  port:       options[:port],
  password:   options[:password],
  api_token:  options[:api_token],
  from_time:  options[:from_time],
  until_time: options[:until_time],
  output_dir: options[:output_dir],
).run
