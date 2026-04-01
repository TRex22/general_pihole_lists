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
require 'json'
require 'uri'
require 'optparse'
require 'fileutils'
require 'thread'
require 'set'
require 'time'
require 'date'

FEED_BASE_URL   = 'https://thehackernews.com/feeds/posts/default'
MAX_RESULTS     = 25  # Blogger API; website shows ~24-25 per page
DEFAULT_YEARS   = 2
DEFAULT_PARALLEL = 5

# Cache file lives next to this script; added to .gitignore
CACHE_FILE_DEFAULT  = File.join(__dir__, 'thn_scrape_cache.json')
OUTPUT_FILE_DEFAULT = File.join(__dir__, '..', 'blocklists', 'malicious.txt')

# RFC-compliant domain label structure. No network access — purely structural.
VALID_DOMAIN_RE = /\A(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\z/

# Minimum seconds between any two outbound HTTP requests (all threads share this).
# Caps effective request rate at ~5 req/s regardless of parallelism.
MIN_REQUEST_INTERVAL = 0.2

class THNScraper
  def initialize(years:, parallel:, output_file:, cache_file:, dry_run:)
    @years           = years
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
    puts 'The Hacker News Malicious Domain Scraper'
    puts '=' * 50
    puts "Scraping articles from the last #{@years} year(s)"
    puts "Parallel workers : #{@parallel}"
    puts "Output file      : #{@output_file}"
    puts "Cache file       : #{@cache_file}"
    puts "Dry run          : #{@dry_run}"
    puts

    articles = collect_article_urls
    puts "\nTotal articles to process: #{articles.size}\n\n"

    scrape_articles_parallel(articles)

    write_to_blocklist unless @dry_run

    save_cache
    print_summary
  end

  private

  # ──────────────────────────────────────────────────────────────────────────
  # Article collection via Blogger JSON feed API
  # ──────────────────────────────────────────────────────────────────────────

  def collect_article_urls
    puts 'Collecting article URLs from Blogger feed...'

    cutoff = Date.today << (@years * 12)
    current_max = Time.now.utc
    articles = []
    seen = Set.new
    page = 1

    loop do
      encoded = URI.encode_www_form_component(current_max.strftime('%Y-%m-%dT%H:%M:%S+00:00'))
      url = "#{FEED_BASE_URL}?updated-max=#{encoded}&max-results=#{MAX_RESULTS}&alt=json"

      puts "  Page #{page}: before #{current_max.strftime('%Y-%m-%d %H:%M UTC')}"

      response = fetch_with_retry(url)
      unless response
        puts '  -> Failed, stopping article collection.'
        break
      end

      data = JSON.parse(response.body)
      entries = data.dig('feed', 'entry') || []

      if entries.empty?
        puts '  -> No entries returned, done.'
        break
      end

      oldest_time = nil
      new_count   = 0
      hit_cutoff  = false

      entries.each do |entry|
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

        articles << {
          url:      href,
          date_str: published.to_date.to_s,
          title:    entry.dig('title', '$t')&.strip
        }
        new_count += 1
      end

      puts "  -> #{new_count} articles added (total #{articles.size})"

      break if hit_cutoff || new_count == 0

      # Step back just before the oldest entry on this page for next request
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

  # ──────────────────────────────────────────────────────────────────────────
  # Parallel article scraping
  # ──────────────────────────────────────────────────────────────────────────

  def scrape_articles_parallel(articles)
    puts "Scraping articles with #{@parallel} parallel workers...\n"

    queue = Queue.new
    articles.each { |a| queue << a }

    workers = @parallel.times.map do
      Thread.new do
        loop do
          article = begin
            queue.pop(true)
          rescue ThreadError
            nil
          end
          break unless article

          scrape_article(article)
        end
      end
    end

    workers.each(&:join)
  end

  def scrape_article(article)
    url = article[:url]

    @mutex.synchronize do
      cached = @cache['articles'][url]
      if cached
        puts "  [CACHED] #{url} (#{cached['domains']&.size || 0} domains)"
        if cached['domains']&.any? && !cached['written_to_blocklist']
          @pending[url] = {
            domains: cached['domains'],
            title:   cached['title'],
            date:    cached['date']
          }
        end
        return
      end
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

    sleep 0.3
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

    # Also scan code/pre blocks which often contain IOCs
    doc.css('code, pre, tt, kbd, blockquote').each do |node|
      scan_text_for_domains(node.text, domains)
    end

    domains.to_a.sort
  end

  def scan_text_for_domains(text, domains)
    # Find any sequence containing [.] and extract valid domain candidates
    text.scan(/[a-zA-Z0-9][a-zA-Z0-9.\-]*\[\.\][a-zA-Z0-9.\-]*[a-zA-Z0-9]/) do |match|
      candidate = normalize_domain(match)
      domains << candidate if valid_domain?(candidate)
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

  # ──────────────────────────────────────────────────────────────────────────
  # Output
  # ──────────────────────────────────────────────────────────────────────────

  def write_to_blocklist
    return if @pending.empty?

    existing = read_existing_blocklist_domains

    entries_to_write = {}
    @pending.each do |url, data|
      new_domains = data[:domains].reject { |d| existing.include?(d.downcase) }
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
    with_domains       = articles.count { |_, v| v['domains_found'].to_i > 0 }
    total_domains      = articles.sum { |_, v| v['domains_found'].to_i }
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
  years:       DEFAULT_YEARS,
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
          "Years of history to scrape (default: #{DEFAULT_YEARS})") do |n|
    options[:years] = n
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
  parallel:    options[:parallel],
  output_file: options[:output_file],
  cache_file:  options[:cache_file],
  dry_run:     options[:dry_run]
).run
