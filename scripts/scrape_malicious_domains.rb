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
#   ruby scripts/scrape_malicious_domains.rb --browser-fetch --rescan-images
#   ruby scripts/scrape_malicious_domains.rb --skip-ocr
#   ruby scripts/scrape_malicious_domains.rb --ocr-only
#   ruby scripts/scrape_malicious_domains.rb --sources bleepingcomputer,talos
#   ruby scripts/scrape_malicious_domains.rb --sources thehackernews
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
DEFAULT_PARALLEL   = 20 # 5
DEFAULT_PAGES_BACK = 2

CACHE_FILE_DEFAULT  = File.join(__dir__, 'malicious_domains_cache.json')
OUTPUT_FILE_DEFAULT = File.join(__dir__, '..', 'blocklists', 'malicious.txt')

# macOS Vision OCR helper — compiled on first use, reused thereafter.
OCR_MACOS_SCRIPT  = File.join(__dir__, 'ocr_macos.swift')
OCR_MACOS_BINARY  = File.join(__dir__, 'ocr_macos')
OCR_COMPILE_MUTEX    = Mutex.new
BROWSER_FETCH_MUTEX  = Mutex.new  # Serialize Safari/browser fetches (one tab at a time)

# RFC-compliant domain label structure. No network access — purely structural.
VALID_DOMAIN_RE = /\A(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\z/

# Minimum seconds between any two outbound HTTP requests (all threads share this).
# Caps effective request rate at ~5 req/s regardless of parallelism.
MIN_REQUEST_INTERVAL = 0.2

# All defanged-dot separator variants used in the security community
DEFANGED_SEP_PAT = '\[\.' \
                   '\]|\(' \
                   '\.\)|' \
                   '\[DOT\]|\[dot\]|\(DOT\)|\(dot\)'

# A token containing at least one defanged separator (domain or IP candidate)
DEFANGED_TOKEN_RE = /[a-zA-Z0-9][a-zA-Z0-9.\-]*(?:\[\.\]|\(\.\)|\[DOT\]|\[dot\]|\(DOT\)|\(dot\))[a-zA-Z0-9.\-]*[a-zA-Z0-9]/

# Plain IPv4 (used in IoC sections where plain text is expected)
PLAIN_IPV4_RE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/

# IoC section heading strings (downcased, matched with include?)
IOC_HEADINGS = %w[
  indicators\ of\ compromise
  indicators\ of\ compromise\ (iocs)
  indicators\ of\ compromise\ (ioc)
  ioc\ list
  network\ indicators
  ip\ addresses\ and\ domains
].freeze

# Domains (and their subdomains) that are never themselves malicious — they appear in
# security articles as attack targets, platforms, or reference links.
# Subdomain cascade: "api.youtube.com" matches "youtube.com" in this list.
SKIP_DOMAINS = Set.new(%w[
  youtube.com youtu.be
  twitter.com x.com t.co
  facebook.com instagram.com linkedin.com
  reddit.com
  telegram.org t.me api.telegram.org
  discord.com discord.gg discordapp.com discordapp.net
  tiktok.com tiktokv.com tiktokcdn.com tiktokcdn-us.com musical.ly snssdk.com bytedance.com
  google.com gmail.com googleapis.com gstatic.com googletagmanager.com
  googleusercontent.com app.google drive.google.com
  appsheet.com
  microsoft.com outlook.com office.com office365.com visualstudio.com
  windows.com live.com hotmail.com bing.com microsoftonline.com azure.com
  apple.com icloud.com
  amazon.com amazon.pl amazonaws.com
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
  npmjs.com registry.npmjs.org pypi.org rubygems.org
  stackoverflow.com stackexchange.com
  docker.com kubernetes.io
  debian.org ubuntu.com redhat.com
  protonmail.com proton.me proofpoint.com
  chatgpt.com claude.ai deepseek.com huggingface.co
  semgrep.dev cursor.com cursor.sh cursor.so
  blogspot.com archive.org
  7-zip.org brew.sh example.com
  dropbox.com dropboxstatic.com
  isc.sans.edu sans.org sans.edu
  polyfill.io polyfill.com
  temp.sh
  letsencrypt.org digicert.com sectigo.com comodo.com ssl.com usertrust.com
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
  golang.org pkg.go.dev
  jsdelivr.net cdnjs.cloudflare.com
  pastebin.com paste.ee
  shodan.io
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

# Known-safe IP addresses that appear legitimately in security articles
# (public DNS resolvers, CDN anycast addresses, etc.) — never block these.
SKIP_IPS = Set.new(%w[
  8.8.8.8 8.8.4.4
  1.1.1.1 1.0.0.1
  9.9.9.9 149.112.112.112
  208.67.222.222 208.67.220.220
]).freeze

# ────────────────────────────────────────────────────────────────────────────
# Base scraper — shared HTTP, domain validation, blocklist I/O, cache I/O
# ────────────────────────────────────────────────────────────────────────────

class BaseScraper
  def initialize(output_file:, cache:, full_cache:, cache_file:, dry_run:, browser_fetch: false, skip_ocr: false)
    @output_file     = File.expand_path(output_file)
    @cache           = cache        # this source's slice: { 'articles' => {}, 'last_updated' => nil }
    @full_cache      = full_cache   # entire cache hash (written to disk)
    @cache_file      = File.expand_path(cache_file)
    @dry_run         = dry_run
    @browser_fetch   = browser_fetch
    @skip_ocr        = skip_ocr
    @pending         = {}
    @mutex           = Mutex.new
    @request_mutex   = Mutex.new
    @last_request_at = Time.now - MIN_REQUEST_INTERVAL
  end

  private

  # ── Domain helpers ──────────────────────────────────────────────────────────

  def refang(text)
    text
      .gsub('[.]', '.')
      .gsub('(.)', '.')
      .gsub(/\[DOT\]/i, '.')
      .gsub(/\(DOT\)/i, '.')
      .gsub(/hxxps?:\/\//i, 'https://')
      .gsub(/h\*\*ps?:\/\//i, 'https://')
  end

  def valid_ipv4?(str)
    return false unless str =~ /\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/
    str.split('.').all? { |o| (0..255).cover?(o.to_i) }
  end

  def strip_ioc_noise(raw)
    raw
      .gsub(/[\/\?#].*\z/, '')   # strip path/query/fragment
      .gsub(/:.*\z/, '')          # strip port
      .gsub(/[.,;:!?)]+\z/, '')   # strip trailing punctuation
      .chomp('.')
      .downcase
      .strip
  end

  def normalize_domain(raw)
    strip_ioc_noise(refang(raw))
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
    # Safe IP addresses (DNS resolvers, anycast, etc.)
    return true if SKIP_IPS.include?(domain)
    # Exact-only match: root CDN/cloud domains too broad to cascade to subdomains
    return true if EXACT_SKIP_DOMAINS.include?(domain)
    # Subdomain cascade: "api.youtube.com" matches "youtube.com"
    SKIP_DOMAINS.any? { |s| domain == s || domain.end_with?(".#{s}") }
  end

  def scan_for_iocs(text, domains, ips, plain_text: false)
    return if text.nil? || text.empty?

    # --- Defanged tokens (any context) ---
    text.scan(DEFANGED_TOKEN_RE) do |m|
      candidate = normalize_domain(m)
      if valid_ipv4?(candidate)
        ips << candidate unless SKIP_IPS.include?(candidate)
      elsif valid_domain?(candidate) && !skip_domain?(candidate)
        domains << candidate
      end
    end

    # hxxp:// / hxxps:// URLs
    text.scan(/hxxps?:\/\/([^\s\[\]()\"'<>\x00-\x1f]+)/i) do |m|
      host = strip_ioc_noise(m[0])
      if valid_ipv4?(host)
        ips << host unless SKIP_IPS.include?(host)
      elsif valid_domain?(host) && !skip_domain?(host)
        domains << host
      end
    end

    # h**p:// / h**ps:// URLs
    text.scan(/h\*\*ps?:\/\/([^\s\[\]()\"'<>\x00-\x1f]+)/i) do |m|
      host = strip_ioc_noise(m[0])
      if valid_ipv4?(host)
        ips << host unless SKIP_IPS.include?(host)
      elsif valid_domain?(host) && !skip_domain?(host)
        domains << host
      end
    end

    return unless plain_text

    # --- Plain text (only in IoC sections) ---
    text.scan(PLAIN_IPV4_RE) do |m|
      ip = strip_ioc_noise(m)
      ips << ip if valid_ipv4?(ip) && !SKIP_IPS.include?(ip)
    end

    # Plain domains — conservative (validated by valid_domain?)
    text.scan(/\b([a-zA-Z0-9][a-zA-Z0-9\-]{0,62}(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,62})+)\b/) do |m|
      candidate = strip_ioc_noise(m[0])
      next if candidate.match?(/\A[\d.]+\z/)  # skip pure numeric (already caught as IP)
      next if candidate.match?(/\A\d+\.\d+[\.\d]*\z/)  # version strings
      if valid_domain?(candidate) && !skip_domain?(candidate)
        domains << candidate
      end
    end
  end

  # Backward-compatible wrapper
  def scan_text_for_domains(text, domains)
    ips = Set.new
    scan_for_iocs(text, domains, ips)
  end

  def extract_ioc_section(doc, headings: IOC_HEADINGS)
    doc.css('h1,h2,h3,h4,h5,h6,strong,b,th,td').each do |node|
      text = node.text.strip.downcase
      next unless headings.any? { |h| text.include?(h) }

      # Walk forward siblings collecting text until the next heading
      ioc_parts = []
      sib = node.next_sibling
      while sib
        break if sib.element? && sib.name.match?(/\Ah[1-6]\z/i)
        ioc_parts << sib.text
        sib = sib.next_sibling
      end

      # Also grab the parent's following siblings if that yielded nothing
      if ioc_parts.join.strip.empty?
        parent = node.parent
        sib = parent&.next_sibling
        while sib
          break if sib.element? && sib.name.match?(/\Ah[1-6]\z/i)
          ioc_parts << sib.text
          sib = sib.next_sibling
        end
      end

      result = ioc_parts.join("\n").strip
      return result unless result.empty?
    end
    nil
  end

  def article_content(doc)
    doc.at_css('article, .article-body, .post-body, .entry-content, .articlebody, #articlebody, main, .content') ||
      doc.at_css('body')
  end

  def image_skip_fragments
    %w[
      doubleclick.net googlesyndication.com adserv advert
      /pixel. /1x1. /tracking /beacon /analytics /stat.
      /social/ /share-button /twitter-bird /fb-button /whatsapp
      /favicon /apple-touch-icon /touch-icon
      gravatar.com /avatar/ /author- /author_
      /logo. /badge. /icon-
      feeds.feedburner.com
    ]
  end

  def extract_images(doc, base_url)
    content = article_content(doc)
    return [] unless content

    base_uri = URI.parse(base_url)
    seen     = Set.new
    images   = []

    content.css('img').each do |img|
      src = nil
      %w[src data-src data-lazy-src data-original data-lazy].each do |attr|
        val = img[attr]&.strip
        next if val.nil? || val.empty? || val.start_with?('data:')
        src = val
        break
      end
      src ||= img['srcset']&.split(/[\s,]+/)&.find { |s| !s.start_with?('data:') && s.include?('.') }

      next if src.nil? || src.strip.empty?

      url = resolve_url(src, base_uri)
      next unless url&.start_with?('http')
      next if image_skip_fragments.any? { |f| url.downcase.include?(f) }

      w = img['width']&.to_i
      h = img['height']&.to_i
      next if (w && w.positive? && w < 50) || (h && h.positive? && h < 50)

      next unless seen.add?(url)
      images << url
    end

    images
  end

  def resolve_url(src, base_uri)
    URI.join(base_uri, src).to_s
  rescue URI::Error
    src.start_with?('http') ? src : nil
  end

  def most_recent_cached_date
    return nil if @cache['articles'].empty?
    @cache['articles'].values
      .filter_map { |a| Date.parse(a['date']) rescue nil }
      .max
  end

  def rescan_images_in_cache
    if @ocr_only
      puts "\nOCR-only mode: re-fetching images and re-running OCR on all cached articles..."
    else
      puts "\nImage rescan: checking cached articles for unprocessed screenshots..."
    end

    to_scan = @cache['articles'].select do |_, entry|
      if @ocr_only
        entry['images'].nil? || entry['images'].is_a?(Array)
      else
        entry['images'].nil? ||
          (entry['images'].is_a?(Array) && entry['images'].any? && entry['images_ocr_at'].nil?)
      end
    end

    if to_scan.empty?
      puts '  No cached articles to process.'
      return
    end

    puts "  Articles to rescan: #{to_scan.size}"

    to_scan.each do |url, entry|
      puts "  [RESCAN] #{url}"

      if entry['images'].nil?
        html = nil

        if @browser_fetch && browser_fetch_available?
          puts "    Trying Safari browser fetch..."
          html = fetch_via_browser(url)
          html = nil if html && cloudflare_challenge?(html)
        end

        if html.nil?
          response = fetch_with_retry(url)
          unless response
            warn "  [FAILED] #{url}"
            next
          end
          if cloudflare_challenge?(response.body)
            if @browser_fetch
              warn "  [CF-BLOCK] #{url} — Cloudflare challenge; browser fetch also failed"
            else
              warn "  [CF-BLOCK] #{url} — Cloudflare challenge; try --browser-fetch"
            end
            next
          end
          html = response.body
        end

        doc = Nokogiri::HTML(html)
        entry['images'] = extract_images(doc, url)
        puts "    Found #{entry['images'].size} image(s)"
      end

      images = entry['images']
      if images.empty?
        entry['images_ocr_at'] = Time.now.utc.iso8601
        save_cache(quiet: true)
        next
      end

      ocr_domains = extract_domains_from_images(images)
      entry['images_ocr_at']     = Time.now.utc.iso8601
      entry['image_ocr_domains'] = ocr_domains.to_a.sort

      if ocr_domains.empty?
        save_cache(quiet: true)
        next
      end

      existing_domains = Set.new(entry['domains'] || [])
      new_domains      = ocr_domains - existing_domains

      unless new_domains.empty?
        entry['domains']              = (existing_domains | ocr_domains).to_a.sort
        entry['written_to_blocklist'] = false

        @pending[url] = {
          domains: new_domains.to_a.sort,
          title:   entry['title'],
          date:    entry['date']
        }

        puts "    [OCR +#{new_domains.size}] #{url}"
        new_domains.each { |d| puts "               #{d}" }
      end

      save_cache(quiet: true)
    end
  end

  def scrape_articles_parallel(articles)
    workers = [parallel_workers, articles.size].min
    batches = articles.each_slice(workers).to_a
    batches.tqdm(desc: 'Scraping articles', total: batches.size, unit: 'batch').each do |batch|
      threads = batch.map { |a| Thread.new { scrape_article(a) } }
      threads.each(&:join)
      sleep batch_delay if batch_delay.positive?
      save_cache(quiet: true)
    end
  end

  # Override in subclasses to limit concurrency or add inter-batch delays.
  def parallel_workers = @parallel
  def batch_delay      = 0

  # Default no-op for scrapers without Cloudflare protection
  def cloudflare_challenge?(_html) = false

  # ── HTTP ────────────────────────────────────────────────────────────────────

  def fetch_via_browser(url, wait_seconds: 5)
    escaped = url.gsub('\\', '\\\\').gsub('"', '\\"')

    script = <<~APPLESCRIPT
      tell application "Safari"
        activate
        make new document with properties {URL:"#{escaped}"}
        delay #{wait_seconds}
        set pageSource to source of document 1
        close document 1
        return pageSource
      end tell
    APPLESCRIPT

    BROWSER_FETCH_MUTEX.synchronize do
      result = IO.popen(['osascript', '-e', script], err: File::NULL, &:read)
      $?.success? && !result.strip.empty? ? result : nil
    end
  rescue StandardError => e
    warn "  Browser fetch error for #{url}: #{e.message}"
    nil
  end

  def browser_fetch_available?
    return @browser_fetch_available if defined?(@browser_fetch_available)
    @browser_fetch_available = RUBY_PLATFORM.include?('darwin') &&
                               system('which osascript > /dev/null 2>&1')
  end

  # Default request headers — subclasses may override for site-specific needs.
  # Using a realistic browser UA prevents many bot-detection 403s.
  def request_headers
    {
      'User-Agent'      => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      'Accept'          => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language' => 'en-US,en;q=0.9'
    }
  end

  def fetch_with_retry(url, retries: 3)
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
          headers: request_headers,
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

  def ocr_backend
    @ocr_backend ||= detect_ocr_backend
  end

  def detect_ocr_backend
    if RUBY_PLATFORM.include?('darwin')
      if File.exist?(OCR_MACOS_SCRIPT) &&
         (system('which swiftc > /dev/null 2>&1') || system('which swift > /dev/null 2>&1'))
        return :macos
      end
    end

    return :tesseract if system('which tesseract > /dev/null 2>&1')

    nil
  end

  def warn_orange(msg)
    if $stderr.isatty
      warn "\e[33m#{msg}\e[0m"
    else
      warn msg
    end
  end

  def warn_if_no_ocr_backend
    return if ocr_backend

    warn_orange('Warning: no OCR backend found — images will be cached but not scanned for domains.')
    if RUBY_PLATFORM.include?('darwin')
      warn_orange('  macOS: install Xcode Command Line Tools  →  xcode-select --install')
    end
    warn_orange('  Linux/Windows: install Tesseract  →  https://github.com/tesseract-ocr/tesseract')
  end

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

  def ocr_image_url(image_url)
    return nil unless ocr_backend

    ensure_macos_ocr_compiled if ocr_backend == :macos

    response = HTTParty.get(
      image_url,
      headers: request_headers,
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

  def extract_domains_from_images(image_urls)
    domains = Set.new
    return domains if image_urls.empty? || ocr_backend.nil? || @skip_ocr

    image_urls.each do |url|
      text = ocr_image_url(url)
      next if text.nil? || text.empty?
      scan_text_for_domains(text, domains)
    end

    domains
  end

  # ── Blocklist ───────────────────────────────────────────────────────────────

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

      has_domains && !still_has_domains ? nil : filtered
    end

    if removed.empty?
      puts 'No skip-listed entries found in blocklist — nothing to clean.'
      return
    end

    puts "Removed #{removed.size} skip-listed entr#{removed.size == 1 ? 'y' : 'ies'} from #{@output_file}:"
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

    domain_sources = {}
    @pending.each do |url, data|
      data[:domains].each do |d|
        domain_sources[d] ||= []
        domain_sources[d] << url unless domain_sources[d].include?(url)
      end
    end

    new_domain_sources = domain_sources.reject { |d, _| existing.include?(d) }
    dup_domain_sources = domain_sources.select { |d, _| existing.include?(d) }

    add_source_comments_for_duplicates(dup_domain_sources) if dup_domain_sources.any?

    if new_domain_sources.empty?
      puts "\nAll found domains already present in blocklist — nothing new to append." if dup_domain_sources.empty?
      mark_pending_written
      return
    end

    source_set_groups = {}
    new_domain_sources.each do |domain, urls|
      source_set_groups[urls] ||= []
      source_set_groups[urls] << domain
    end

    total = new_domain_sources.size
    puts "\nAppending #{total} new domain(s) to #{@output_file}"

    File.open(@output_file, 'a') do |f|
      f.puts
      source_set_groups.each do |urls, domains|
        urls.each { |url| f.puts "# Source: #{url}" }
        domains.sort.each { |d| f.puts d }
        f.puts
      end
    end

    mark_pending_written
  end

  def add_source_comments_for_duplicates(dup_domain_sources)
    return unless File.exist?(@output_file)

    sections = parse_sections(File.readlines(@output_file, chomp: true))
    added_count = 0

    sections.each do |section|
      next if section == :blank

      section_domains = section
        .reject { |l| l.strip.start_with?('#') }
        .map    { |l| l.split('#').first.strip.downcase }
        .to_set

      urls_to_add = []
      dup_domain_sources.each do |domain, urls|
        next unless section_domains.include?(domain)
        urls.each { |u| urls_to_add << u unless urls_to_add.include?(u) }
      end
      next if urls_to_add.empty?

      existing_sources = section
        .select { |l| l.strip.start_with?('# Source:') }
        .map(&:strip)
        .to_set

      new_sources = urls_to_add.reject { |u| existing_sources.include?("# Source: #{u}") }
      next if new_sources.empty?

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
# StandardPaginatedScraper — base for all URL-paginated scrapers
# ────────────────────────────────────────────────────────────────────────────

class StandardPaginatedScraper < BaseScraper
  # Subclasses MUST define:
  #   SOURCE_NAME = '...'
  #   SOURCE_KEY  = '...'
  #   BASE_URL    = 'https://...'
  #
  # Subclasses MUST implement:
  #   listing_url(page)      → String
  #   parse_listing(doc)     → [{url:, title:, date_str:, date: Date|nil}]
  #
  # Subclasses MAY override:
  #   ioc_headings           → [String]  (downcased, matched with include?)
  #   skip_article?(url)     → bool
  #   max_pages              → Integer (hard cap, default 500)
  #   article_content(doc)   → Nokogiri node (from BaseScraper default)
  #   image_skip_fragments   → [String]  (from BaseScraper default)

  def initialize(years:, pages_back:, parallel:, output_file:, cache:, full_cache:,
                 cache_file:, dry_run:, browser_fetch: false, skip_ocr: false,
                 ocr_only: false, lookback_days: nil, **_opts)
    super(output_file: output_file, cache: cache, full_cache: full_cache,
          cache_file: cache_file, dry_run: dry_run, browser_fetch: browser_fetch,
          skip_ocr: skip_ocr)
    @years         = years
    @pages_back    = pages_back
    @lookback_days = lookback_days
    @parallel      = parallel
    @ocr_only      = ocr_only
  end

  def run
    puts "Mode             : #{@ocr_only ? 'OCR-only (no scraping)' : mode_label}"
    puts "Parallel workers : #{@parallel}" unless @ocr_only
    puts "Output file      : #{@output_file}"
    puts "Cache file       : #{@cache_file}"
    puts "Dry run          : #{@dry_run}"
    puts "OCR backend      : #{@skip_ocr ? 'skipped (--skip-ocr)' : (ocr_backend || 'none')}"
    puts "Browser fetch    : #{@browser_fetch}"
    puts

    warn_if_no_ocr_backend
    ensure_macos_ocr_compiled if ocr_backend == :macos

    if @ocr_only
      rescan_images_in_cache
    else
      articles = collect_article_urls
      puts "\nTotal articles to process: #{articles.size}\n\n"
      scrape_articles_parallel(articles) if articles.any?
    end

    unless @dry_run
      clean_blocklist
      write_to_blocklist
    end

    save_cache
    print_summary
  end

  private

  def ioc_headings
    IOC_HEADINGS
  end

  def skip_article?(_url)
    false
  end

  def max_pages
    500
  end

  def mode_label
    last = most_recent_cached_date
    if @years
      "full scan (#{@years} year(s))"
    elsif last
      overlap = @lookback_days&.positive? ? "#{@lookback_days}-day lookback" : "#{@pages_back} pages back"
      "incremental (#{overlap} from #{last})"
    else
      "first run — full scan (#{DEFAULT_YEARS} year(s))"
    end
  end

  def collect_article_urls
    articles    = []
    seen        = Set.new
    cutoff      = Date.today << ((@years || DEFAULT_YEARS) * 12)
    last_date   = most_recent_cached_date
    incremental = @years.nil? && !last_date.nil?
    pages_beyond = 0

    puts "Collecting article URLs..."

    (1..max_pages).each do |page|
      url  = listing_url(page)
      puts "  Page #{page}: #{url}"

      resp = fetch_with_retry(url)
      unless resp
        puts "  -> Failed, stopping."
        break
      end

      doc     = Nokogiri::HTML(resp.body)
      entries = parse_listing(doc)

      if entries.empty?
        puts "  -> No entries, done."
        break
      end

      oldest_date = nil
      new_count   = 0
      hit_cutoff  = false

      entries.each do |entry|
        next if seen.include?(entry[:url])
        seen.add(entry[:url])
        next if skip_article?(entry[:url])

        date = entry[:date]

        # Track oldest date seen on this page *before* the cutoff check so
        # we can stop the page loop even if the per-entry break fires early.
        oldest_date = date if date && (oldest_date.nil? || date < oldest_date)

        if date && date < cutoff
          hit_cutoff = true
          break
        end

        next if @cache['articles'][entry[:url]]

        articles << entry
        new_count += 1
      end

      puts "  -> #{new_count} new (total #{articles.size})"
      # Stop if a cutoff was hit mid-loop OR the oldest date on the page
      # is already beyond the cutoff (catches nil-date scrapers once a
      # dated entry finally appears past the boundary).
      break if hit_cutoff || (oldest_date && oldest_date < cutoff)

      if incremental && oldest_date
        if @lookback_days&.positive?
          break if oldest_date < (last_date - @lookback_days)
        elsif oldest_date < last_date
          pages_beyond += 1
          break if pages_beyond >= @pages_back
        end
      end

      sleep 0.5
    end

    articles
  end

  def scrape_article(article)
    url  = article[:url]
    resp = fetch_with_retry(url)
    unless resp
      @mutex.synchronize { puts "  [FAILED  ] #{url}" }
      return
    end

    doc   = Nokogiri::HTML(resp.body)
    title = article[:title] || doc.at_css('h1')&.text&.strip

    domains  = Set.new
    ips      = Set.new
    content  = article_content(doc)
    scan_for_iocs(content&.text.to_s, domains, ips)

    ioc_text = extract_ioc_section(doc, headings: ioc_headings)
    scan_for_iocs(ioc_text.to_s, domains, ips, plain_text: true)

    images   = extract_images(doc, url)
    ocr_doms = extract_domains_from_images(images)
    domains.merge(ocr_doms)

    all_found = (domains.to_a + ips.to_a).sort.uniq

    entry = {
      'url'                  => url,
      'title'                => title,
      'date'                 => article[:date_str],
      'scraped_at'           => Time.now.utc.iso8601,
      'domains'              => all_found,
      'images'               => images,
      'image_ocr_domains'    => ocr_doms.to_a.sort,
      'images_ocr_at'        => (images.any? && ocr_backend && !@skip_ocr ? Time.now.utc.iso8601 : nil),
      'written_to_blocklist' => false
    }

    @mutex.synchronize do
      @cache['articles'][url] = entry
      label = all_found.any? ? "[FOUND #{all_found.size.to_s.rjust(3)}]" : '[NO DOMAINS ]'
      puts "  #{label} #{url}"
      all_found.each { |d| puts "               #{d}" }
      puts "               (#{images.size} image(s), #{ocr_doms.size} via OCR)" if images.any?
      @pending[url] = { domains: all_found, title: title, date: article[:date_str] } if all_found.any?
    end
  end
end

# ────────────────────────────────────────────────────────────────────────────
# Load scrapers
# ────────────────────────────────────────────────────────────────────────────

require_relative 'scrapers/thehackernews'
require_relative 'scrapers/bleepingcomputer'
require_relative 'scrapers/krebsonsecurity'
require_relative 'scrapers/isc_sans'
require_relative 'scrapers/talos'
require_relative 'scrapers/unit42'
require_relative 'scrapers/securelist'
require_relative 'scrapers/malwarebytes'
require_relative 'scrapers/welivesecurity'
require_relative 'scrapers/proofpoint'
require_relative 'scrapers/microsoft_security'
require_relative 'scrapers/google_threat_intel'
require_relative 'scrapers/anyrun'

ALL_SCRAPERS = {
  'thehackernews'       => THNScraper,
  'bleepingcomputer'    => BleepingComputerScraper,
  'krebsonsecurity'     => KrebsScraper,
  'isc_sans'            => ISCSansScraper,
  'talos'               => TalosScraper,
  'unit42'              => Unit42Scraper,
  'securelist'          => SecurelistScraper,
  'malwarebytes'        => MalwarebyteScraper,
  'welivesecurity'      => WeLiveSecurityScraper,
  'proofpoint'          => ProofpointScraper,
  'microsoft_security'  => MicrosoftSecurityScraper,
  'google_threat_intel' => GoogleThreatIntelScraper,
  'anyrun'              => AnyRunScraper,
}.freeze

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
  rescan_images:  false,            # re-OCR cached articles that have images not yet processed
  browser_fetch:  false,            # use Safari via osascript to fetch Cloudflare-protected pages
  skip_ocr:       false,            # cache images but do not run OCR
  ocr_only:       false,            # skip article scraping; only re-OCR cached images
  sources:        nil,              # nil = all; comma-separated SOURCE_KEYs to restrict
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

  opts.on('--browser-fetch',
          'Use Safari (macOS only) to fetch Cloudflare-protected article pages for image extraction') do
    options[:browser_fetch] = true
  end

  opts.on('--skip-ocr',
          'Cache image URLs but skip OCR (useful for fast runs or when OCR is slow)') do
    options[:skip_ocr] = true
  end

  opts.on('--ocr-only',
          'Skip article scraping; re-fetch images and re-run OCR on all cached articles') do
    options[:ocr_only] = true
  end

  opts.on('--sources KEYS',
          'Comma-separated source keys to scrape (default: all). E.g.: thehackernews,bleepingcomputer') do |v|
    options[:sources] = v.split(',').map(&:strip).map(&:downcase)
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
all_sources_label = "all (#{ALL_SCRAPERS.keys.join(', ')})"
puts "Sources     : #{options[:sources] ? options[:sources].join(', ') : all_sources_label}"

full_cache = load_full_cache(options[:cache_file])

scrapers_to_run = if options[:sources]
  ALL_SCRAPERS.select { |k, _| options[:sources].include?(k) }
else
  ALL_SCRAPERS
end

if scrapers_to_run.empty?
  warn "No matching scrapers for: #{options[:sources].join(', ')}"
  warn "Available: #{ALL_SCRAPERS.keys.join(', ')}"
  exit 1
end

scrapers_to_run.each do |source_key, klass|
  source_name = klass::SOURCE_NAME
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
      rescan_images: options[:rescan_images],
      browser_fetch: options[:browser_fetch],
      skip_ocr:      options[:skip_ocr],
      ocr_only:      options[:ocr_only]
    ).run
  rescue StandardError => e
    warn "Error scraping #{source_name}: #{e.message}"
    warn e.backtrace.first(5).join("\n") if e.backtrace
  end
end
