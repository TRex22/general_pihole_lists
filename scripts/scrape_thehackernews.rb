#!/usr/bin/env ruby
# frozen_string_literal: true

# The Hacker News Malicious Domain Scraper
#
# Scrapes THN articles for domains written with [.] obfuscation (e.g. evil[.]com)
# and appends them to blocklists/malicious.txt.
#
# Uses Blogger's JSON feed API for article listing (reliable, structured).
# Scrapes individual article HTML pages for domain extraction.
#
# Usage:
#   ruby scripts/scrape_thehackernews.rb
#   ruby scripts/scrape_thehackernews.rb --years 3
#   ruby scripts/scrape_thehackernews.rb --parallel 10
#   ruby scripts/scrape_thehackernews.rb --dry-run
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

FEED_BASE_URL   = 'https://thehackernews.com/feeds/posts/default'
MAX_RESULTS     = 25  # Blogger API; website shows ~24-25 per page
DEFAULT_YEARS      = 2
DEFAULT_PARALLEL   = 5
DEFAULT_PAGES_BACK = 2

# Cache file lives next to this script; added to .gitignore
CACHE_FILE_DEFAULT  = File.join(__dir__, 'thn_scrape_cache.json')
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

class THNScraper
  def initialize(years:, pages_back:, parallel:, output_file:, cache_file:, dry_run:)
    @years           = years       # nil → incremental mode; Integer → full mode
    @pages_back      = pages_back
    @parallel        = parallel
    @output_file     = File.expand_path(output_file)
    @cache_file      = File.expand_path(cache_file)
    @dry_run         = dry_run
    @cache           = load_cache
    @mutex           = Mutex.new
    @request_mutex   = Mutex.new
    @last_request_at = Time.now - MIN_REQUEST_INTERVAL
    @pending         = {}
  end

  def run
    last_scraped = most_recent_cached_date
    incremental  = @years.nil? && !last_scraped.nil?

    puts 'The Hacker News Malicious Domain Scraper'
    puts '=' * 50
    if incremental
      puts "Mode             : incremental (#{@pages_back} pages back from #{last_scraped})"
    elsif @years
      puts "Mode             : full scan (#{@years} year(s))"
    else
      puts "Mode             : first run — full scan (#{DEFAULT_YEARS} year(s))"
    end
    puts "Parallel workers : #{@parallel}"
    puts "Output file      : #{@output_file}"
    puts "Cache file       : #{@cache_file}"
    puts "Dry run          : #{@dry_run}"
    puts

    articles = collect_article_urls
    puts "\nTotal articles to process: #{articles.size}\n\n"

    scrape_articles_parallel(articles)

    unless @dry_run
      clean_blocklist
      write_to_blocklist
    end

    save_cache
    print_summary
  end

  private

  # ──────────────────────────────────────────────────────────────────────────
  # Article collection via Blogger JSON feed API
  # ──────────────────────────────────────────────────────────────────────────

  def collect_article_urls
    last_scraped     = most_recent_cached_date
    incremental      = @years.nil? && !last_scraped.nil?
    cutoff           = incremental ? Date.today << (DEFAULT_YEARS * 12) : Date.today << ((@years || DEFAULT_YEARS) * 12)
    pages_beyond_last = 0

    puts 'Collecting article URLs from Blogger feed...'

    current_max = Time.now.utc
    articles    = []
    seen        = Set.new
    page        = 1

    loop do
      encoded = URI.encode_www_form_component(current_max.strftime('%Y-%m-%dT%H:%M:%S+00:00'))
      url     = "#{FEED_BASE_URL}?updated-max=#{encoded}&max-results=#{MAX_RESULTS}&alt=json"

      puts "  Page #{page}: before #{current_max.strftime('%Y-%m-%d %H:%M UTC')}"

      response = fetch_with_retry(url)
      unless response
        puts '  -> Failed, stopping article collection.'
        break
      end

      data    = JSON.parse(response.body)
      entries = data.dig('feed', 'entry') || []

      if entries.empty?
        puts '  -> No entries returned, done.'
        break
      end

      oldest_time = nil
      new_count   = 0
      hit_cutoff  = false

      entries.tqdm(desc: "Page #{page}", unit: 'entry', leave: false).each do |entry|
        href = alternate_link(entry)
        next if href.nil? || seen.include?(href)
        seen.add(href)

        published = parse_time(entry.dig('published', '$t'))
        next unless published

        if published.to_date < cutoff
          hit_cutoff = true
          break
        end

        oldest_time = published if oldest_time.nil? || published < oldest_time

        # Skip re-scraping if the article is in cache and hasn't been updated since.
        # The Blogger feed's "updated" timestamp changes when the post content changes.
        feed_updated_at = entry.dig('updated', '$t')
        cached_entry    = @cache['articles'][href]
        force_rescrape  = cached_entry && cached_entry['feed_updated_at'] != feed_updated_at

        next if cached_entry && !force_rescrape

        articles << {
          url:             href,
          date_str:        published.to_date.to_s,
          title:           entry.dig('title', '$t')&.strip,
          feed_updated_at: feed_updated_at,
          force_rescrape:  force_rescrape
        }
        new_count += 1
      end

      puts "  -> #{new_count} new article(s) queued (total #{articles.size})"

      break if hit_cutoff

      # Guard against a stuck cursor (all entries on this page were already seen/skipped)
      if oldest_time.nil?
        puts '  -> No advanceable entries on page, stopping.'
        break
      end

      # Incremental mode: stop after @pages_back pages whose oldest article
      # predates the most recently cached article — this is the overlap window.
      if incremental && oldest_time.to_date < last_scraped
        pages_beyond_last += 1
        if pages_beyond_last >= @pages_back
          puts "  -> #{@pages_back} overlap page(s) fetched past #{last_scraped}, stopping."
          break
        end
      end

      current_max = oldest_time - 1
      page += 1
      sleep 0.5
    end

    articles
  end

  def alternate_link(entry)
    entry['link']&.find { |l| l['rel'] == 'alternate' }&.dig('href')
  end

  def parse_time(str)
    Time.parse(str)
  rescue StandardError
    nil
  end

  def most_recent_cached_date
    return nil if @cache['articles'].empty?

    @cache['articles'].values
      .filter_map { |a| Date.parse(a['date']) rescue nil }
      .max
  end

  # ──────────────────────────────────────────────────────────────────────────
  # Parallel article scraping
  # ──────────────────────────────────────────────────────────────────────────

  def scrape_articles_parallel(articles)
    batches = articles.each_slice(@parallel).to_a
    batches.tqdm(desc: 'Scraping articles', total: batches.size, unit: 'batch').each do |batch|
      threads = batch.map { |article| Thread.new { scrape_article(article) } }
      threads.each(&:join)
    end
  end

  def scrape_article(article)
    url = article[:url]

    # collect_article_urls only enqueues articles that are new or force_rescrape,
    # so a cached entry here means it was updated since last scrape.
    if article[:force_rescrape]
      @mutex.synchronize { puts "  [UPDATED ] #{url} — re-scraping" }
    end

    response = fetch_with_retry(url)
    unless response
      @mutex.synchronize { puts "  [FAILED] #{url}" }
      return
    end

    doc     = Nokogiri::HTML(response.body)
    domains = extract_domains(doc)
    title   = article[:title] || doc.at_css('h1.post-title, h1')&.text&.strip

    entry = {
      'url'                  => url,
      'title'                => title,
      'date'                 => article[:date_str],
      'feed_updated_at'      => article[:feed_updated_at],
      'scraped_at'           => Time.now.utc.iso8601,
      'domains'              => domains,
      'written_to_blocklist' => false
    }

    @mutex.synchronize do
      @cache['articles'][url] = entry

      if domains.any?
        @pending[url] = { domains: domains, title: title, date: article[:date_str] }
        puts "  [FOUND #{domains.size.to_s.rjust(3)}] #{url}"
        domains.each { |d| puts "               #{d}" }
      else
        puts "  [NO DOMAINS ] #{url}"
      end
    end
  end

  # ──────────────────────────────────────────────────────────────────────────
  # Domain extraction
  # ──────────────────────────────────────────────────────────────────────────

  def extract_domains(doc)
    domains = Set.new

    content = doc.at_css('.articlebody, .article-body, .post-body, #articlebody, article .entry-content, main') ||
              doc.at_css('body')
    return [] unless content

    scan_text_for_domains(content.text, domains)
    domains.to_a.sort
  end

  def scan_text_for_domains(text, domains)
    # Find any sequence containing [.] and extract valid domain candidates
    text.scan(/[a-zA-Z0-9][a-zA-Z0-9.\-]*\[\.\][a-zA-Z0-9.\-]*[a-zA-Z0-9]/) do |match|
      candidate = normalize_domain(match)
      domains << candidate if valid_domain?(candidate) && !skip_domain?(candidate)
    end
  end

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

  # ──────────────────────────────────────────────────────────────────────────
  # Output
  # ──────────────────────────────────────────────────────────────────────────

  def clean_blocklist
    return unless File.exist?(@output_file)

    lines = File.readlines(@output_file, chomp: true)
    removed = []

    # Split into sections on blank lines so we can drop orphaned source blocks
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

    # Reconstruct, collapsing consecutive blanks into one
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

        # Mark written in cache
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
        # Strip inline comments like `domain.com # note`
        set << line.split('#').first.strip.downcase
      end
    end
  end

  # ──────────────────────────────────────────────────────────────────────────
  # Cache
  # ──────────────────────────────────────────────────────────────────────────

  def load_cache
    return empty_cache unless File.exist?(@cache_file)

    JSON.parse(File.read(@cache_file))
  rescue JSON::ParserError => e
    warn "Warning: cache corrupt, starting fresh. (#{e.message})"
    empty_cache
  end

  def empty_cache
    { 'articles' => {}, 'last_updated' => nil }
  end

  def save_cache
    @cache['last_updated'] = Time.now.utc.iso8601
    FileUtils.mkdir_p(File.dirname(@cache_file))
    File.write(@cache_file, JSON.pretty_generate(@cache))
    puts "Cache saved: #{@cache_file}"
  end

  # ──────────────────────────────────────────────────────────────────────────
  # HTTP
  # ──────────────────────────────────────────────────────────────────────────

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

  # ──────────────────────────────────────────────────────────────────────────
  # Summary
  # ──────────────────────────────────────────────────────────────────────────

  def print_summary
    articles = @cache['articles']
    total              = articles.size
    with_domains       = articles.count { |_, v| v['domains']&.any? }
    total_domains      = articles.sum { |_, v| v['domains']&.size.to_i }
    written_articles   = articles.count { |_, v| v['written_to_blocklist'] }

    puts
    puts '=' * 50
    puts 'Summary'
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
          "Cache JSON file (default: scripts/thn_scrape_cache.json)") do |f|
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

THNScraper.new(
  years:       options[:years],
  pages_back:  options[:pages_back],
  parallel:    options[:parallel],
  output_file: options[:output_file],
  cache_file:  options[:cache_file],
  dry_run:     options[:dry_run]
).run
