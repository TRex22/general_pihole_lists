#!/usr/bin/env ruby
# frozen_string_literal: true

# Malicious Domain Scraper
#
# Scrapes security news sites for domains written with [.] obfuscation (e.g. evil[.]com)
# and appends them to blocklists/malicious.txt.
#
# Usage:
#   ruby scripts/scrape_malicious_domains.rb
#   ruby scripts/scrape_malicious_domains.rb --years 3
#   ruby scripts/scrape_malicious_domains.rb --parallel 10
#   ruby scripts/scrape_malicious_domains.rb --dry-run
#
# WARNING: Extracted domains are NEVER accessed/resolved. Validation is regex-only.

require 'httparty'
require 'nokogiri'
require 'tqdm'
require 'json'
require 'uri'
require 'optparse'
require 'fileutils'
require 'set'
require 'time'
require 'date'

DEFAULT_YEARS      = 2
DEFAULT_PARALLEL   = 5
DEFAULT_PAGES_BACK = 2

CACHE_FILE_DEFAULT  = File.join(__dir__, 'malicious_domains_cache.json')
OUTPUT_FILE_DEFAULT = File.join(__dir__, '..', 'blocklists', 'malicious.txt')

# RFC-compliant domain label structure. No network access — purely structural.
VALID_DOMAIN_RE = /\A(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\z/

# Minimum seconds between any two outbound HTTP requests (all threads share this).
# Caps effective request rate at ~5 req/s regardless of parallelism.
MIN_REQUEST_INTERVAL = 0.2

# Domains (and their subdomains) that are never themselves malicious — they appear in
# security articles as attack targets, platforms, or reference links.
# Subdomain cascade: "api.youtube.com" matches "youtube.com" in this list.
SKIP_DOMAINS = Set.new(%w[
  youtube.com youtu.be
  twitter.com x.com t.co
  facebook.com instagram.com linkedin.com
  reddit.com telegram.org t.me
  discord.com discord.gg
  google.com gmail.com googleapis.com gstatic.com googletagmanager.com
  googleusercontent.com app.google
  appsheet.com
  microsoft.com outlook.com office.com office365.com visualstudio.com
  windows.com live.com hotmail.com bing.com microsoftonline.com azure.com
  apple.com icloud.com
  amazon.com amazon.pl
  cloudflare.com bootcdn.net bootcss.com
  github.com githubusercontent.com github.dev
  gitlab.com bitbucket.org
  wikipedia.org wikimedia.org
  apache.org
  thehackernews.com
  virustotal.com shodan.io censys.io urlscan.io
  hybrid-analysis.com any.run
  abuse.ch threatfox.abuse.ch urlhaus.abuse.ch bazaar.abuse.ch
  talosintelligence.com mitre.org cve.mitre.org
  nvd.nist.gov nist.gov cisa.gov
  bleepingcomputer.com krebsonsecurity.com
  darkreading.com securityweek.com threatpost.com
  techcrunch.com wired.com arstechnica.com zdnet.com
  reuters.com bbc.com bbc.co.uk cnn.com
  oracle.com salesforce.com adobe.com
  paypal.com stripe.com
  wordpress.com wordpress.org
  php.net python.org ruby-lang.org nodejs.org
  npmjs.com pypi.org rubygems.org
  stackoverflow.com stackexchange.com
  docker.com kubernetes.io
  debian.org ubuntu.com redhat.com
  protonmail.com proton.me
  chatgpt.com claude.ai deepseek.com huggingface.co
  blogspot.com archive.org
  7-zip.org brew.sh example.com
  etherscan.io binance.com metamask.io coinbasepro.com localbitcoins.com
  ip-api.com ipapi.co ipinfo.io ipgeolocation.io
  matrix.org meta.com msn.com vk.com trello.com
  mail.ru rambler.ru ukr.net
  notepad-plus-plus.org open-vsx.org pkg.go.dev unpkg.com vscode.dev
  dictionary.com indeed.com zohomail.com
  tinyurl.com tiny.cc qrco.de
  gainsightcloud.com ustream.tv langchain.com aha.io petapixel.com
  caixa.gov.br terra.com.br
  btgpactual.com itau.com.br safra.com.br santandernet.com.br
  bancooriginal.com.br bitcointrade.com.br foxbit.com.br
  bilibili.com 126.com 163.com
  dnspod.cn dnspod.com
  facebook.net facebookmail.com
  doubleclick.net sohu.com sohu.com.cn
]).freeze

# Root-level cloud/CDN platform domains that are too broad to block wholesale —
# adding them here removes only the bare root entry from malicious.txt without
# cascading to subdomains (e.g. a specific malicious workers.dev subdomain stays blockable).
EXACT_SKIP_DOMAINS = Set.new(%w[
  azureedge.net
  azurefd.net
  windows.net
  workers.dev
  cloudfunctions.net
]).freeze

# ────────────────────────────────────────────────────────────────────────────
# Base scraper — shared HTTP, domain validation, blocklist I/O, cache I/O
# ────────────────────────────────────────────────────────────────────────────

class BaseScraper
  def initialize(output_file:, cache:, full_cache:, cache_file:, dry_run:)
    @output_file     = File.expand_path(output_file)
    @cache           = cache        # this source's slice: { 'articles' => {}, 'last_updated' => nil }
    @full_cache      = full_cache   # entire cache hash (written to disk)
    @cache_file      = File.expand_path(cache_file)
    @dry_run         = dry_run
    @pending         = {}
    @mutex           = Mutex.new
    @request_mutex   = Mutex.new
    @last_request_at = Time.now - MIN_REQUEST_INTERVAL
  end

  private

  # ── Domain helpers ──────────────────────────────────────────────────────────

  def normalize_domain(raw)
    raw
      .gsub('[.]', '.')   # de-obfuscate
      .gsub(/\/.*\z/, '') # strip path
      .gsub(/#.*\z/, '')  # strip fragment
      .chomp('.')
      .downcase
      .strip
  end

  def valid_domain?(domain)
    return false if domain.nil? || domain.empty?
    return false if domain.length > 253
    return false if domain.include?('*')
    return false if domain.include?(':')
    return false if domain.include?('/')
    return false if domain == 'localhost'
    return false if /\A\d+\.\d+\.\d+\.\d+\z/.match?(domain)  # pure IPv4
    return false unless domain.include?('.')

    VALID_DOMAIN_RE.match?(domain)
  end

  def skip_domain?(domain)
    return false if domain.nil? || domain.empty?
    # Exact-only match: root CDN/cloud domains too broad to cascade to subdomains
    return true if EXACT_SKIP_DOMAINS.include?(domain)
    # Subdomain cascade: "api.youtube.com" matches "youtube.com"
    SKIP_DOMAINS.any? { |s| domain == s || domain.end_with?(".#{s}") }
  end

  def scan_text_for_domains(text, domains)
    # Find any sequence containing [.] and extract valid domain candidates
    text.scan(/[a-zA-Z0-9][a-zA-Z0-9.\-]*\[\.\][a-zA-Z0-9.\-]*[a-zA-Z0-9]/) do |match|
      candidate = normalize_domain(match)
      domains << candidate if valid_domain?(candidate) && !skip_domain?(candidate)
    end
  end

  # ── HTTP ────────────────────────────────────────────────────────────────────

  def fetch_with_retry(url, retries: 3)
    # Reserve a slot in the global request timeline before making the call.
    # Sleep is done outside the mutex so other threads aren't blocked while waiting.
    delay = @request_mutex.synchronize do
      elapsed = Time.now - @last_request_at
      wait = [MIN_REQUEST_INTERVAL - elapsed, 0].max
      @last_request_at = Time.now + wait
      wait
    end
    sleep(delay) if delay > 0

    retries.times do |attempt|
      begin
        response = HTTParty.get(
          url,
          headers: {
            'User-Agent' => 'Mozilla/5.0 (compatible; pihole-list-builder/1.0; domain scraper)',
            'Accept'     => 'text/html,application/xhtml+xml,application/xml,application/json;q=0.9,*/*;q=0.8'
          },
          timeout:          30,
          follow_redirects: true
        )

        return response if response.success?

        warn "  HTTP #{response.code} for #{url} (attempt #{attempt + 1}/#{retries})"
      rescue StandardError => e
        warn "  Error: #{e.message} for #{url} (attempt #{attempt + 1}/#{retries})"
      end

      sleep(1 * (attempt + 1)) unless attempt == retries - 1
    end

    nil
  end

  # ── Blocklist ───────────────────────────────────────────────────────────────

  def clean_blocklist
    return unless File.exist?(@output_file)

    lines = File.readlines(@output_file, chomp: true)
    removed = []

    sections = []
    current  = []
    lines.each do |line|
      if line.strip.empty?
        sections << current unless current.empty?
        sections << :blank
        current = []
      else
        current << line
      end
    end
    sections << current unless current.empty?

    clean_sections = sections.map do |section|
      next :blank if section == :blank

      has_domains = section.any? { |l| !l.strip.start_with?('#') }

      filtered = section.reject do |l|
        stripped = l.strip
        next false if stripped.start_with?('#')
        domain = stripped.split('#').first.strip.downcase
        if skip_domain?(domain)
          removed << domain
          true
        else
          false
        end
      end

      still_has_domains = filtered.any? { |l| !l.strip.start_with?('#') }

      # Drop entire section if it had domains but all were removed
      has_domains && !still_has_domains ? nil : filtered
    end

    if removed.empty?
      puts 'No skip-listed domains found in blocklist — nothing to clean.'
      return
    end

    puts "Removed #{removed.size} skip-listed domain(s) from #{@output_file}:"
    removed.each { |d| puts "  - #{d}" }

    output_lines = []
    clean_sections.each do |section|
      next if section.nil?
      if section == :blank
        output_lines << '' unless output_lines.last == ''
      else
        output_lines.concat(section)
      end
    end

    File.write(@output_file, output_lines.join("\n").strip + "\n")
  end

  def write_to_blocklist
    return if @pending.empty?

    existing = read_existing_blocklist_domains

    entries_to_write = {}
    @pending.each do |url, data|
      new_domains = data[:domains].reject { |d| existing.include?(d) }
      entries_to_write[url] = data.merge(domains: new_domains) if new_domains.any?
    end

    if entries_to_write.empty?
      puts "\nAll found domains already present in blocklist — nothing to append."
      return
    end

    total = entries_to_write.values.sum { |d| d[:domains].size }
    puts "\nAppending #{total} new domain(s) across #{entries_to_write.size} source(s) to #{@output_file}"

    File.open(@output_file, 'a') do |f|
      f.puts  # blank line separator before new block
      entries_to_write.each do |url, data|
        f.puts "# Source: #{url}"
        data[:domains].each { |d| f.puts d }
        f.puts

        @cache['articles'][url]['written_to_blocklist'] = true if @cache['articles'][url]
      end
    end
  end

  def read_existing_blocklist_domains
    return Set.new unless File.exist?(@output_file)

    Set.new.tap do |set|
      File.foreach(@output_file) do |line|
        line = line.strip
        next if line.empty? || line.start_with?('#')
        set << line.split('#').first.strip.downcase
      end
    end
  end

  # ── Cache ───────────────────────────────────────────────────────────────────

  def save_cache
    @cache['last_updated']      = Time.now.utc.iso8601
    @full_cache['last_updated'] = Time.now.utc.iso8601
    FileUtils.mkdir_p(File.dirname(@cache_file))
    File.write(@cache_file, JSON.pretty_generate(@full_cache))
    puts "Cache saved: #{@cache_file}"
  end

  # ── Summary ─────────────────────────────────────────────────────────────────

  def print_summary
    articles         = @cache['articles']
    total            = articles.size
    with_domains     = articles.count { |_, v| v['domains']&.any? }
    total_domains    = articles.sum   { |_, v| v['domains']&.size.to_i }
    written_articles = articles.count { |_, v| v['written_to_blocklist'] }

    puts
    puts '=' * 50
    puts "Summary: #{self.class::SOURCE_NAME}"
    puts '=' * 50
    puts "Articles in cache          : #{total}"
    puts "Articles with domains      : #{with_domains}"
    puts "Total domains found (all)  : #{total_domains}"
    puts "Articles written to output : #{written_articles}"
    puts "Output                     : #{@output_file}"
    puts "Cache                      : #{@cache_file}"
  end
end

# ────────────────────────────────────────────────────────────────────────────
# Load scrapers
# ────────────────────────────────────────────────────────────────────────────

require_relative 'scrapers/thehackernews'

SCRAPERS = [THNScraper].freeze

# ────────────────────────────────────────────────────────────────────────────
# Cache file helpers
# ────────────────────────────────────────────────────────────────────────────

def load_full_cache(cache_file)
  # Auto-migrate from old thn_scrape_cache.json if the new file doesn't exist yet
  old_cache_file = File.join(File.dirname(cache_file), 'thn_scrape_cache.json')
  if !File.exist?(cache_file) && File.exist?(old_cache_file)
    puts "Migrating cache: #{old_cache_file} -> #{cache_file}"
    old_data = JSON.parse(File.read(old_cache_file))
    migrated = if old_data.key?('articles')
      { 'thehackernews' => { 'articles' => old_data['articles'], 'last_updated' => old_data['last_updated'] } }
    else
      old_data
    end
    FileUtils.mkdir_p(File.dirname(cache_file))
    File.write(cache_file, JSON.pretty_generate(migrated))
    return migrated
  end

  return {} unless File.exist?(cache_file)

  data = JSON.parse(File.read(cache_file))
  # Handle any stray old flat format
  if data.key?('articles')
    { 'thehackernews' => { 'articles' => data['articles'], 'last_updated' => data['last_updated'] } }
  else
    data
  end
rescue JSON::ParserError => e
  warn "Warning: cache corrupt, starting fresh. (#{e.message})"
  {}
end

# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────

options = {
  years:       nil,                 # nil = incremental if cache exists, else DEFAULT_YEARS full scan
  pages_back:  DEFAULT_PAGES_BACK,
  parallel:    DEFAULT_PARALLEL,
  output_file: OUTPUT_FILE_DEFAULT,
  cache_file:  CACHE_FILE_DEFAULT,
  dry_run:     false
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} [options]"
  opts.separator ''
  opts.separator 'Options:'

  opts.on('-y', '--years N', Integer,
          "Full scan: go back N years (overrides incremental mode)") do |n|
    options[:years] = n
  end

  opts.on('-b', '--pages-back N', Integer,
          "Incremental mode: overlap pages before last cached date (default: #{DEFAULT_PAGES_BACK})") do |n|
    options[:pages_back] = n
  end

  opts.on('-p', '--parallel N', Integer,
          "Parallel worker threads (default: #{DEFAULT_PARALLEL})") do |n|
    options[:parallel] = n
  end

  opts.on('-o', '--output FILE',
          "Output blocklist file (default: blocklists/malicious.txt)") do |f|
    options[:output_file] = f
  end

  opts.on('-c', '--cache FILE',
          "Cache JSON file (default: scripts/malicious_domains_cache.json)") do |f|
    options[:cache_file] = f
  end

  opts.on('--dry-run',
          'Scrape and cache but do not write to blocklist') do
    options[:dry_run] = true
  end

  opts.on('-h', '--help', 'Show this help') do
    puts opts
    exit
  end
end.parse!

puts 'Malicious Domain Scraper'
puts '=' * 60
puts "Output file : #{File.expand_path(options[:output_file])}"
puts "Cache file  : #{File.expand_path(options[:cache_file])}"
puts "Dry run     : #{options[:dry_run]}"

full_cache = load_full_cache(options[:cache_file])

SCRAPERS.each do |klass|
  source_name = klass::SOURCE_NAME
  source_key  = klass::SOURCE_KEY

  puts
  puts "=== Scraping: #{source_name} ==="
  puts

  source_cache = full_cache[source_key] ||= { 'articles' => {}, 'last_updated' => nil }

  begin
    klass.new(
      years:       options[:years],
      pages_back:  options[:pages_back],
      parallel:    options[:parallel],
      output_file: options[:output_file],
      cache:       source_cache,
      full_cache:  full_cache,
      cache_file:  options[:cache_file],
      dry_run:     options[:dry_run]
    ).run
  rescue StandardError => e
    warn "Error scraping #{source_name}: #{e.message}"
    warn e.backtrace.first(3).join("\n") if e.backtrace
  end
end
