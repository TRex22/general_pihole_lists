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
#   ruby scripts/scrape_malicious_domains.rb --lookback-days 14
#   ruby scripts/scrape_malicious_domains.rb --years 3 --rescan-images
#
# WARNING: Extracted domains are NEVER accessed/resolved. Validation is regex-only.

require 'httparty'
require 'nokogiri'
require 'tqdm'
require 'json'
require 'uri'
require 'optparse'
require 'fileutils'
require 'tempfile'
require 'set'
require 'time'
require 'date'

DEFAULT_YEARS      = 2
DEFAULT_PARALLEL   = 10 # 5
DEFAULT_PAGES_BACK = 2

CACHE_FILE_DEFAULT  = File.join(__dir__, 'malicious_domains_cache.json')
OUTPUT_FILE_DEFAULT = File.join(__dir__, '..', 'blocklists', 'malicious.txt')

# macOS Vision OCR helper — compiled on first use, reused thereafter.
OCR_MACOS_SCRIPT  = File.join(__dir__, 'ocr_macos.swift')
OCR_MACOS_BINARY  = File.join(__dir__, 'ocr_macos')
OCR_COMPILE_MUTEX = Mutex.new

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

  # ── OCR ─────────────────────────────────────────────────────────────────────

  # Returns :macos, :tesseract, or nil. Memoised per instance.
  def ocr_backend
    @ocr_backend ||= detect_ocr_backend
  end

  def detect_ocr_backend
    # macOS: prefer Vision framework via compiled Swift helper.
    if RUBY_PLATFORM.include?('darwin')
      if File.exist?(OCR_MACOS_SCRIPT) &&
         (system('which swiftc > /dev/null 2>&1') || system('which swift > /dev/null 2>&1'))
        return :macos
      end
    end

    # Any platform: fall back to tesseract if it's in PATH.
    return :tesseract if system('which tesseract > /dev/null 2>&1')

    nil
  end

  # Print an orange/amber warning to stderr (colour only when stderr is a TTY).
  def warn_orange(msg)
    if $stderr.isatty
      warn "\e[33m#{msg}\e[0m"
    else
      warn msg
    end
  end

  # Call once at scraper startup to surface a clear warning when OCR is absent.
  def warn_if_no_ocr_backend
    return if ocr_backend

    warn_orange('Warning: no OCR backend found — images will be cached but not scanned for domains.')
    if RUBY_PLATFORM.include?('darwin')
      warn_orange('  macOS: install Xcode Command Line Tools  →  xcode-select --install')
    end
    warn_orange('  Linux/Windows: install Tesseract  →  https://github.com/tesseract-ocr/tesseract')
  end

  # Compile the Swift OCR helper once; thread-safe via OCR_COMPILE_MUTEX.
  # Falls back to :tesseract (or nil) if compilation fails.
  def ensure_macos_ocr_compiled
    OCR_COMPILE_MUTEX.synchronize do
      return if File.exist?(OCR_MACOS_BINARY)
      puts '  Compiling macOS OCR helper (one-time)...'
      success = system('swiftc', OCR_MACOS_SCRIPT, '-o', OCR_MACOS_BINARY)
      unless success && File.exist?(OCR_MACOS_BINARY)
        warn_orange('  Warning: could not compile macOS OCR helper — falling back to tesseract')
        @ocr_backend = system('which tesseract > /dev/null 2>&1') ? :tesseract : nil
      end
    end
  end

  # Download an image URL to a temp file, run OCR, return the recognised text.
  # Returns nil on any error so callers can simply skip.
  def ocr_image_url(image_url)
    return nil unless ocr_backend

    ensure_macos_ocr_compiled if ocr_backend == :macos

    response = HTTParty.get(
      image_url,
      headers: { 'User-Agent' => 'Mozilla/5.0 (compatible; pihole-list-builder/1.0; domain scraper)' },
      timeout: 30,
      follow_redirects: true
    )
    return nil unless response.success?

    ext = image_extension_from(image_url, response.headers['content-type'])

    Tempfile.create(['ocr_img', ext]) do |tmp|
      tmp.binmode
      tmp.write(response.body)
      tmp.flush

      case ocr_backend
      when :macos
        text = IO.popen([OCR_MACOS_BINARY, tmp.path], err: File::NULL, &:read)
        $?.success? ? text : nil
      when :tesseract
        # --psm 11: sparse text — finds as much text as possible (best for screenshots)
        text = IO.popen(['tesseract', tmp.path, 'stdout', '--psm', '11'], err: File::NULL, &:read)
        $?.success? ? text : nil
      end
    end
  rescue StandardError => e
    warn "  OCR error for #{image_url}: #{e.message}"
    nil
  end

  def image_extension_from(url, content_type)
    case content_type&.split(';')&.first&.strip
    when 'image/png'  then '.png'
    when 'image/jpeg' then '.jpg'
    when 'image/gif'  then '.gif'
    when 'image/webp' then '.webp'
    when 'image/bmp'  then '.bmp'
    else
      url.match(/\.(png|jpe?g|gif|webp|bmp|tiff?)/i)&.[](0) || '.jpg'
    end
  end

  # Run OCR on a list of image URLs and return any domains found.
  def extract_domains_from_images(image_urls)
    domains = Set.new
    return domains if image_urls.empty? || ocr_backend.nil?

    image_urls.each do |url|
      text = ocr_image_url(url)
      next if text.nil? || text.empty?
      scan_text_for_domains(text, domains)
    end

    domains
  end

  # ── Blocklist ───────────────────────────────────────────────────────────────

  # Parse an array of lines into sections separated by blank lines.
  # Returns an array where each element is either :blank or an Array of lines.
  def parse_sections(lines)
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
    sections
  end

  def clean_blocklist
    return unless File.exist?(@output_file)

    lines    = File.readlines(@output_file, chomp: true)
    removed  = []
    sections = parse_sections(lines)

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

    # Build domain → [source_urls] across all pending articles, deduped globally
    domain_sources = {}
    @pending.each do |url, data|
      data[:domains].each do |d|
        domain_sources[d] ||= []
        domain_sources[d] << url unless domain_sources[d].include?(url)
      end
    end

    new_domain_sources = domain_sources.reject { |d, _| existing.include?(d) }
    dup_domain_sources = domain_sources.select { |d, _| existing.include?(d) }

    # For domains already in the blocklist, insert source attribution comments
    add_source_comments_for_duplicates(dup_domain_sources) if dup_domain_sources.any?

    if new_domain_sources.empty?
      puts "\nAll found domains already present in blocklist — nothing new to append." if dup_domain_sources.empty?
      mark_pending_written
      return
    end

    # Group new domains by their exact set of source URLs so domains shared by
    # multiple articles get a single block with multiple # Source: lines.
    source_set_groups = {}
    new_domain_sources.each do |domain, urls|
      source_set_groups[urls] ||= []
      source_set_groups[urls] << domain
    end

    total = new_domain_sources.size
    puts "\nAppending #{total} new domain(s) to #{@output_file}"

    File.open(@output_file, 'a') do |f|
      f.puts  # blank line separator before new block
      source_set_groups.each do |urls, domains|
        urls.each { |url| f.puts "# Source: #{url}" }
        domains.sort.each { |d| f.puts d }
        f.puts
      end
    end

    mark_pending_written
  end

  # Insert new # Source: comments into existing sections for domains that are
  # already in the blocklist, so every source that found the domain is credited.
  def add_source_comments_for_duplicates(dup_domain_sources)
    return unless File.exist?(@output_file)

    sections = parse_sections(File.readlines(@output_file, chomp: true))
    added_count = 0

    sections.each do |section|
      next if section == :blank

      # Domains present in this section
      section_domains = section
        .reject { |l| l.strip.start_with?('#') }
        .map    { |l| l.split('#').first.strip.downcase }
        .to_set

      # Collect new source URLs for any domain in this section
      urls_to_add = []
      dup_domain_sources.each do |domain, urls|
        next unless section_domains.include?(domain)
        urls.each { |u| urls_to_add << u unless urls_to_add.include?(u) }
      end
      next if urls_to_add.empty?

      # Skip sources already commented in this section
      existing_sources = section
        .select { |l| l.strip.start_with?('# Source:') }
        .map(&:strip)
        .to_set

      new_sources = urls_to_add.reject { |u| existing_sources.include?("# Source: #{u}") }
      next if new_sources.empty?

      # Insert after the last existing # Source: line, or at the top of the section
      last_source_idx = section.rindex { |l| l.strip.start_with?('# Source:') }
      insert_at = last_source_idx ? last_source_idx + 1 : 0

      new_sources.each_with_index do |url, i|
        section.insert(insert_at + i, "# Source: #{url}")
        added_count += 1
      end
    end

    return if added_count.zero?

    output_lines = []
    sections.each do |section|
      if section == :blank
        output_lines << '' unless output_lines.last == ''
      else
        output_lines.concat(section)
      end
    end
    File.write(@output_file, output_lines.join("\n").strip + "\n")

    puts "\nAdded source attribution for #{dup_domain_sources.size} duplicate domain(s) already in blocklist."
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

  def mark_pending_written
    @pending.each_key do |url|
      @cache['articles'][url]['written_to_blocklist'] = true if @cache['articles'][url]
    end
  end

  # ── Cache ───────────────────────────────────────────────────────────────────

  # quiet: true suppresses the confirmation line (used for mid-run checkpoints).
  def save_cache(quiet: false)
    @cache['last_updated']      = Time.now.utc.iso8601
    @full_cache['last_updated'] = Time.now.utc.iso8601
    FileUtils.mkdir_p(File.dirname(@cache_file))
    File.write(@cache_file, JSON.pretty_generate(@full_cache))
    puts "Cache saved: #{@cache_file}" unless quiet
  end

  # ── Summary ─────────────────────────────────────────────────────────────────

  def print_summary
    articles         = @cache['articles']
    total            = articles.size
    with_domains     = articles.count { |_, v| v['domains']&.any? }
    total_domains    = articles.sum   { |_, v| v['domains']&.size.to_i }
    written_articles = articles.count { |_, v| v['written_to_blocklist'] }
    with_images      = articles.count { |_, v| v['images']&.any? }
    total_images     = articles.sum   { |_, v| v['images']&.size.to_i }
    ocr_domain_count = articles.sum   { |_, v| v['image_ocr_domains']&.size.to_i }

    puts
    puts '=' * 50
    puts "Summary: #{self.class::SOURCE_NAME}"
    puts '=' * 50
    puts "Articles in cache          : #{total}"
    puts "Articles with domains      : #{with_domains}"
    puts "Total domains found (all)  : #{total_domains}"
    puts "Articles written to output : #{written_articles}"
    puts "Articles with images       : #{with_images}"
    puts "Total images cached        : #{total_images}"
    puts "Domains found via OCR      : #{ocr_domain_count}"
    puts "OCR backend                : #{ocr_backend || 'none (install tesseract or run on macOS)'}"
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
  years:          nil,              # nil = incremental if cache exists, else DEFAULT_YEARS full scan
  pages_back:     DEFAULT_PAGES_BACK,
  lookback_days:  nil,              # incremental mode: also scan N days before last cached date
  parallel:       DEFAULT_PARALLEL,
  output_file:    OUTPUT_FILE_DEFAULT,
  cache_file:     CACHE_FILE_DEFAULT,
  dry_run:        false,
  rescan_images:  false             # re-OCR cached articles that have images not yet processed
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

  opts.on('-d', '--lookback-days N', Integer,
          'Incremental mode: also scan N days before the last cached article (overrides --pages-back overlap)') do |n|
    options[:lookback_days] = n
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

  opts.on('--rescan-images',
          'Re-OCR images in cached articles not yet processed (runs after normal scrape)') do
    options[:rescan_images] = true
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
      years:         options[:years],
      pages_back:    options[:pages_back],
      lookback_days: options[:lookback_days],
      parallel:      options[:parallel],
      output_file:   options[:output_file],
      cache:         source_cache,
      full_cache:    full_cache,
      cache_file:    options[:cache_file],
      dry_run:       options[:dry_run],
      rescan_images: options[:rescan_images]
    ).run
  rescue StandardError => e
    warn "Error scraping #{source_name}: #{e.message}"
    warn e.backtrace.first(3).join("\n") if e.backtrace
  end
end
