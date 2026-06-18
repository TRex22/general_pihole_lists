#!/usr/bin/env ruby
# frozen_string_literal: true

# Malicious Package Scraper
#
# Builds a database of known malicious packages (npm, PyPI, RubyGems, Cargo,
# NuGet, Go, Maven, etc.) from structured feeds and security blog scraping.
#
# Output: malicious_package_database/malicious_packages.json and malicious_package_database/malicious_packages.csv
#
# Each package entry records every source URL where it was found (sources array).
# The cache in scripts/malicious_packages_cache.json tracks processed articles
# so incremental runs only process new content.
#
# Usage:
#   ruby scripts/scrape_malicious_packages.rb
#   ruby scripts/scrape_malicious_packages.rb --years 2
#   ruby scripts/scrape_malicious_packages.rb --lookback-days 7
#   ruby scripts/scrape_malicious_packages.rb --sources ossf,socket_dev
#   ruby scripts/scrape_malicious_packages.rb --dry-run
#   ruby scripts/scrape_malicious_packages.rb --status

require 'optparse'
require 'csv'
require 'benchmark'
require_relative 'base_scraper'

PKG_DEFAULT_PARALLEL   = 10
PKG_DEFAULT_PAGES_BACK = 2
PKG_DEFAULT_YEARS      = 2

PKG_CACHE_FILE_DEFAULT  = File.join(__dir__, 'malicious_packages_cache.json')
PKG_OUTPUT_DIR_DEFAULT  = File.join(__dir__, '..', 'malicious_package_database')
PKG_JSON_FILE_DEFAULT   = File.join(PKG_OUTPUT_DIR_DEFAULT, 'malicious_packages.json')
PKG_CSV_FILE_DEFAULT    = File.join(PKG_OUTPUT_DIR_DEFAULT, 'malicious_packages.csv')

# ────────────────────────────────────────────────────────────────────────────
# Package extraction patterns
# ────────────────────────────────────────────────────────────────────────────

# Words that look like package names but are not
PACKAGE_SKIP_NAMES = Set.new(%w[
  install update remove add list version help info search init start stop build
  test run publish login logout whoami config cache clean doctor audit fix link
  unlink node python ruby rust golang java php javascript typescript
  npm pip gem cargo dotnet mvn gradle composer pnpm yarn bun
  package module library crate the and for from with into
  true false null none undefined
]).freeze

# High-confidence install-command patterns. Capture group 1 = package name.
PACKAGE_INSTALL_PATTERNS = [
  { re: /\bpip(?:3)?\s+install\s+(?:-[^\s]+\s+)*['"]?([a-zA-Z0-9][a-zA-Z0-9\-_\.]{1,100})['"]?(?:\s|==|[><!]=|$)/,
    type: 'PyPI' },
  { re: /\bnpm\s+(?:install|i|add)\s+(?:--?[\w-]+(?:\s+[^\s]+)?\s+)*['"]?(@?[a-zA-Z0-9][a-zA-Z0-9\-_\.@\/]{1,100})['"]?(?:\s|@\d|$)/,
    type: 'npm' },
  { re: /\byarn\s+add\s+(?:--?[\w-]+(?:\s+[^\s]+)?\s+)*['"]?(@?[a-zA-Z0-9][a-zA-Z0-9\-_\.@\/]{1,100})['"]?(?:\s|@\d|$)/,
    type: 'npm' },
  { re: /\bpnpm\s+(?:add|install)\s+(?:--?[\w-]+(?:\s+[^\s]+)?\s+)*['"]?(@?[a-zA-Z0-9][a-zA-Z0-9\-_\.@\/]{1,100})['"]?(?:\s|@\d|$)/,
    type: 'npm' },
  { re: /\bbun\s+add\s+(?:--?[\w-]+(?:\s+[^\s]+)?\s+)*['"]?(@?[a-zA-Z0-9][a-zA-Z0-9\-_\.@\/]{1,100})['"]?(?:\s|@\d|$)/,
    type: 'npm' },
  { re: /\bgem\s+install\s+['"]?([a-zA-Z0-9][a-zA-Z0-9\-_\.]{1,100})['"]?(?:\s|$)/,
    type: 'RubyGems' },
  { re: /\bcargo\s+add\s+['"]?([a-zA-Z0-9][a-zA-Z0-9\-_]{1,100})['"]?(?:\s|$)/,
    type: 'Cargo' },
  { re: /\bdotnet\s+add\s+package\s+['"]?([a-zA-Z0-9][a-zA-Z0-9\-_\.]{1,100})['"]?(?:\s|$)/i,
    type: 'NuGet' },
  { re: /\bgo\s+get\s+['"]?([a-zA-Z0-9][\w\-\.\/]{1,200})['"]?(?:\s|@|$)/,
    type: 'Go' },
  { re: /\bcomposer\s+require\s+['"]?([a-zA-Z0-9][a-zA-Z0-9\-_\.\/]{1,100})['"]?(?:\s|$)/,
    type: 'Packagist' },
  { re: /\b(?:yay|paru|pikaur)\s+(?:-S|--sync|install)\s+(?:-[^\s]+\s+)*['"]?([a-zA-Z0-9][a-zA-Z0-9\-_\.]{1,100})['"]?(?:\s|$)/,
    type: 'AUR' },
].freeze

# High-confidence contextual mention patterns. Capture group 1 = package name.
PACKAGE_MENTION_PATTERNS = [
  # "malicious/backdoored npm package 'evil-pkg'"
  { re: /(?:malicious|backdoored?|trojanized|infected|fake|rogue|typosquatt?\w*|stealer)\s+(?:npm|node\.?js?)\s+(?:package|module|library)\s+[`'""\[]([a-zA-Z0-9@][a-zA-Z0-9\-_\.@\/]{1,100})[`'""\]]/i,
    type: 'npm' },
  { re: /(?:malicious|backdoored?|trojanized|infected|fake|rogue|typosquatt?\w*|stealer)\s+(?:PyPI|pip(?:3)?|python)\s+(?:package|module|library)\s+[`'""\[]([a-zA-Z0-9][a-zA-Z0-9\-_\.]{1,100})[`'""\]]/i,
    type: 'PyPI' },
  { re: /(?:malicious|backdoored?|trojanized|infected|fake|rogue|typosquatt?\w*|stealer)\s+(?:Ruby\s*Gems?|gem)\s+(?:package|gem)?\s*[`'""\[]([a-zA-Z0-9][a-zA-Z0-9\-_\.]{1,100})[`'""\]]/i,
    type: 'RubyGems' },
  { re: /(?:malicious|backdoored?|trojanized|infected|fake|rogue|typosquatt?\w*|stealer)\s+(?:NuGet|\.NET|dotnet)\s+(?:package|library)\s+[`'""\[]([a-zA-Z0-9][a-zA-Z0-9\-_\.]{1,100})[`'""\]]/i,
    type: 'NuGet' },
  { re: /(?:malicious|backdoored?|trojanized|infected|fake|rogue|typosquatt?\w*|stealer)\s+(?:Cargo|crates?\.io|Rust)\s+(?:crate|package)\s+[`'""\[]([a-zA-Z0-9][a-zA-Z0-9\-_]{1,100})[`'""\]]/i,
    type: 'Cargo' },
  { re: /(?:malicious|backdoored?|trojanized|infected|fake|rogue|typosquatt?\w*|stealer)\s+(?:Maven|Gradle|Java)\s+(?:artifact|package|library)\s+[`'""\[]([a-zA-Z0-9][a-zA-Z0-9\-_\.:]{1,100})[`'""\]]/i,
    type: 'Maven' },
  # "npm package 'x'" / "PyPI package 'y'" (without explicit malicious prefix)
  { re: /\b(?:npm|node\.?js?)\s+(?:package|module|library)\s+[`'""\[]([a-zA-Z0-9@][a-zA-Z0-9\-_\.@\/]{1,100})[`'""\]]/i,
    type: 'npm' },
  { re: /\b(?:PyPI|pip(?:3)?)\s+(?:package|module|library)\s+[`'""\[]([a-zA-Z0-9][a-zA-Z0-9\-_\.]{1,100})[`'""\]]/i,
    type: 'PyPI' },
  # "package named 'x' on npm/PyPI"
  { re: /\bpackage\s+(?:named?|called)\s+[`'""\[]([a-zA-Z0-9@][a-zA-Z0-9\-_\.@\/]{1,100})[`'""\]]\s+(?:on|in|from|via|to|published(?:\s+on)?)\s+npm\b/i,
    type: 'npm' },
  { re: /\bpackage\s+(?:named?|called)\s+[`'""\[]([a-zA-Z0-9][a-zA-Z0-9\-_\.]{1,100})[`'""\]]\s+(?:on|in|from|via|to|published(?:\s+on)?)\s+(?:PyPI|pip)\b/i,
    type: 'PyPI' },
  # GitHub Actions malicious workflow step
  { re: /(?:malicious|compromised?|backdoored?)\s+(?:GitHub\s+Actions?|action)\s+[`'""\[]([a-zA-Z0-9][a-zA-Z0-9\-_\.@\/]{1,100})[`'""\]]/i,
    type: 'GitHub Actions' },
  # "malicious AUR package 'x'"
  { re: /(?:malicious|backdoored?|trojanized|infected|fake|rogue|typosquatt?\w*|stealer)\s+AUR\s+(?:package|pkgbuild)?\s*[`'""\[]([a-zA-Z0-9][a-zA-Z0-9\-_\.]{1,100})[`'""\]]/i,
    type: 'AUR' },
].freeze

def normalize_package_ecosystem(raw)
  return nil unless raw
  case raw.strip.downcase
  when /\bnpm\b/, /\bnode/, /\bjavascript\b/ then 'npm'
  when /\bpypi\b/, /\bpip\b/, /\bpython\b/   then 'PyPI'
  when /\brubygems?\b/, /\bgem\b/             then 'RubyGems'
  when /\bcargo\b/, /\bcrates?\.io\b/, /\brust\b/ then 'Cargo'
  when /\bnuget\b/, /\bdotnet\b/, /\.net\b/   then 'NuGet'
  when /\bgo(?:lang)?\b/                      then 'Go'
  when /\bmaven\b/, /\bgradle\b/, /\bjava\b/  then 'Maven'
  when /\bcomposer\b/, /\bpackagist\b/, /\bphp\b/ then 'Packagist'
  when /\bhex(?:\.pm)?\b/, /\belixir\b/       then 'Hex'
  when /\bgithub\s+actions?\b/                then 'GitHub Actions'
  when /\baur\b/, /\barch\s+user\s+repository\b/, /\byay\b/, /\bpacman\b/ then 'AUR'
  else raw.strip
  end
end

def valid_package_name?(name, type)
  return false unless name
  name = name.strip
  return false if name.empty? || name.length < 2 || name.length > 214
  return false if name =~ /\s/
  return false if PACKAGE_SKIP_NAMES.include?(name.downcase)
  return false if name =~ /\A[\d\.]+\z/  # pure version string
  # Reject anything that looks like a domain (has .com/.net TLD)
  return false if name =~ /\.(?:com|net|org|io|gov|edu|co)\z/i
  # Reject obvious non-package garbage
  return false if name =~ /\A(?:https?|ftp):\/\//i

  case type
  when 'npm'
    !!(name =~ /\A(@[a-z0-9][\w\-\.]*\/)?[a-z0-9][a-z0-9\-_\.]{0,213}\z/i)
  when 'PyPI'
    !!(name =~ /\A[a-zA-Z0-9][a-zA-Z0-9\-_\.]{0,212}\z/)
  when 'RubyGems'
    !!(name =~ /\A[a-zA-Z0-9][a-zA-Z0-9\-_\.]{0,212}\z/)
  when 'Cargo'
    !!(name =~ /\A[a-zA-Z0-9][a-zA-Z0-9\-_]{0,212}\z/)
  when 'NuGet'
    !!(name =~ /\A[a-zA-Z0-9][a-zA-Z0-9\-_\.]{0,212}\z/)
  when 'Go'
    !!(name =~ /\A[a-zA-Z0-9][a-zA-Z0-9\-_\.\/]{0,212}\z/)
  when 'AUR'
    !!(name =~ /\A[a-z0-9][a-z0-9\-_\.@\+]{0,212}\z/)
  else
    !!(name =~ /\A[a-zA-Z0-9][\w\-_\.@\/]{0,212}\z/)
  end
end

def scan_for_packages(text, found)
  return if text.nil? || text.empty?

  PACKAGE_INSTALL_PATTERNS.each do |p|
    text.scan(p[:re]) do |m|
      name = m[0].to_s.strip.sub(/['""`]$/, '').sub(/^['""`]/, '')
      next unless valid_package_name?(name, p[:type])
      found << { 'name' => name, 'type' => p[:type] }
    end
  end

  PACKAGE_MENTION_PATTERNS.each do |p|
    text.scan(p[:re]) do |m|
      name = m[0].to_s.strip
      next unless valid_package_name?(name, p[:type])
      found << { 'name' => name, 'type' => p[:type] }
    end
  end
end

def deduplicate_packages(found)
  seen = Set.new
  found.select { |p| seen.add?("#{p['name'].downcase}::#{p['type']}") }
end

# ────────────────────────────────────────────────────────────────────────────
# PackageBaseScraper — stripped-down base for all package scrapers
# ────────────────────────────────────────────────────────────────────────────

class PackageBaseScraper < BaseScraper
  def initialize(years:, pages_back:, parallel:, output_file:, cache:, full_cache:,
                 cache_file:, dry_run:, lookback_days: nil, read_timeout: 30, **_opts)
    super(output_file: output_file, cache: cache, full_cache: full_cache,
          cache_file: cache_file, dry_run: dry_run, read_timeout: read_timeout)
    @years         = years
    @pages_back    = pages_back
    @lookback_days = lookback_days
    @parallel      = parallel
  end

  private

  def pkg_scrape_article(article)
    url  = article[:url]
    resp = fetch_with_retry(url)
    unless resp
      @mutex.synchronize { puts "  [FAILED  ] #{url}" }
      return
    end

    doc      = Nokogiri::HTML(resp.body)
    title    = article[:title] || doc.at_css('h1')&.text&.strip
    content  = article_content(doc)
    date_str = article[:date_str] || extract_article_date(doc)&.to_s

    found = []
    scan_for_packages(content&.text.to_s, found)
    doc.css('code, pre, tt').each { |node| scan_for_packages(node.text, found) }
    found = deduplicate_packages(found)

    entry = {
      'url'                 => url,
      'title'               => title,
      'date'                => date_str,
      'scraped_at'          => Time.now.utc.iso8601,
      'packages'            => found,
      'written_to_database' => false
    }

    @mutex.synchronize do
      @cache['articles'][url] = entry
      label = found.any? ? "[FOUND #{found.size.to_s.rjust(3)}]" : '[NO PACKAGES]'
      puts "  #{label} #{url}"
      found.each { |p| puts "               #{p['type']}/#{p['name']}" }
      @pending[url] = { packages: found, title: title, date: date_str } if found.any?
    end
  end

  def pkg_scrape_articles_parallel(articles)
    workers = [parallel_workers, articles.size].min
    batches = articles.each_slice(workers).to_a
    batches.tqdm(desc: 'Scraping articles', total: batches.size, unit: 'batch').each do |batch|
      threads = batch.map { |a| Thread.new { pkg_scrape_article(a) } }
      threads.each(&:join)
      sleep batch_delay if batch_delay.positive?
      save_cache(quiet: true)
    end
  end

  def pkg_print_summary
    articles   = @cache['articles']
    total      = articles.size
    with_pkgs  = articles.count { |_, v| v['packages']&.any? }
    total_pkgs = articles.sum   { |_, v| v['packages']&.size.to_i }

    puts
    puts '=' * 50
    puts "Summary: #{self.class::SOURCE_NAME}"
    puts '=' * 50
    puts "Articles in cache          : #{total}"
    puts "Articles with packages     : #{with_pkgs}"
    puts "Total packages found       : #{total_pkgs}"
    puts "Cache                      : #{@cache_file}"
  end
end

# ────────────────────────────────────────────────────────────────────────────
# PackageStandardPaginatedScraper — pagination + package extraction
# Subclasses define listing_url(page) and parse_listing(doc).
# ────────────────────────────────────────────────────────────────────────────

class PackageStandardPaginatedScraper < PackageBaseScraper
  def run
    last = most_recent_cached_date
    mode = if @years
             "full scan (#{@years} year(s))"
           elsif last
             overlap = @lookback_days&.positive? ? "#{@lookback_days}-day lookback" : "#{@pages_back} pages back"
             "incremental (#{overlap} from #{last})"
           else
             "first run — full scan (#{PKG_DEFAULT_YEARS} year(s))"
           end

    puts "Mode             : #{mode}"
    puts "Parallel workers : #{@parallel}"
    puts "Cache file       : #{@cache_file}"
    puts "Dry run          : #{@dry_run}"
    puts

    articles = collect_article_urls
    puts "\nTotal articles to process: #{articles.size}\n\n"
    pkg_scrape_articles_parallel(articles) if articles.any?

    save_cache
    pkg_print_summary
  end

  private

  def max_pages = 50

  def collect_article_urls
    articles          = []
    seen              = Set.new
    cutoff            = Date.today << ((@years || PKG_DEFAULT_YEARS) * 12)
    last_date         = most_recent_cached_date
    incremental       = @years.nil? && !last_date.nil?
    has_any_cache     = !@cache['articles'].empty?
    pages_beyond      = 0
    consecutive_empty = 0

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
      entries = parse_listing(doc).map { |e| e.merge(url: normalize_wayback_url(e[:url])) }

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

        date = entry[:date]
        oldest_date = date if date && (oldest_date.nil? || date < oldest_date)

        if date && date < cutoff
          hit_cutoff = true
          break
        end

        next if @cache['articles'][entry[:url]]
        articles << entry
        new_count += 1
      end

      # For scrapers whose listing pages carry no dates (Talos, etc.), probe the
      # last article on this page to get a boundary date for the cutoff check.
      oldest_date ||= probe_page_boundary_date(entries)

      puts "  -> #{new_count} new (total #{articles.size})"
      break if hit_cutoff || (oldest_date && oldest_date < cutoff)

      if incremental && oldest_date
        if @lookback_days&.positive?
          break if oldest_date < (last_date - @lookback_days)
        elsif oldest_date < last_date
          pages_beyond += 1
          break if pages_beyond >= @pages_back
        end
      end

      # Stop when pages are fully cached. Applies to all modes except an
      # explicit --years full scan (which must traverse all N years).
      if @years.nil? && new_count == 0 && has_any_cache
        consecutive_empty += 1
        if consecutive_empty >= @pages_back
          puts "  -> #{@pages_back} consecutive fully-cached pages — stopping."
          break
        end
      elsif new_count > 0
        consecutive_empty = 0
      end

      sleep listing_page_delay
    end

    articles
  end
end

# ────────────────────────────────────────────────────────────────────────────
# Database writer — aggregates all cached packages into JSON + CSV
# ────────────────────────────────────────────────────────────────────────────

PKG_TYPE_CANONICAL = {
  'pypi'            => 'PyPI',
  'pip'             => 'PyPI',
  'python'          => 'PyPI',
  'npm'             => 'npm',
  'node'            => 'npm',
  'nodejs'          => 'npm',
  'rubygems'        => 'RubyGems',
  'ruby'            => 'RubyGems',
  'gem'             => 'RubyGems',
  'cargo'           => 'Cargo',
  'crates.io'       => 'Cargo',
  'rust'            => 'Cargo',
  'nuget'           => 'NuGet',
  'dotnet'          => 'NuGet',
  '.net'            => 'NuGet',
  'go'              => 'Go',
  'golang'          => 'Go',
  'maven'           => 'Maven',
  'gradle'          => 'Maven',
  'java'            => 'Maven',
  'packagist'       => 'Packagist',
  'composer'        => 'Packagist',
  'php'             => 'Packagist',
  'hex'             => 'Hex',
  'elixir'          => 'Hex',
  'github actions'  => 'GitHub Actions',
  'github-actions'  => 'GitHub Actions',
  'pub'             => 'Pub',
  'dart'            => 'Pub',
  'swift'           => 'Swift',
  'cocoapods'       => 'CocoaPods',
}.freeze

def canonical_pkg_type(raw)
  PKG_TYPE_CANONICAL[raw.downcase] || raw
end

def write_package_database(full_cache, json_file, csv_file, dry_run: false)
  # Aggregate: key = "name::type", value = {name, type, sources[], dates[]}
  packages = {}

  full_cache.each do |source_key, source_cache|
    next unless source_cache.is_a?(Hash)
    (source_cache['articles'] || {}).each do |_key, entry|
      next unless entry.is_a?(Hash)
      pkgs = entry['packages']
      next unless pkgs&.any?

      source_info = {
        'url'   => entry['url'],
        'title' => entry['title'],
        'date'  => entry['date']
      }.compact

      pkgs.each do |pkg|
        name = pkg['name'].to_s.strip
        type = canonical_pkg_type(pkg['type'].to_s.strip)
        next if name.empty? || type.empty?

        # Canonical key: npm names lowercased, others case-preserved
        canon_name = type == 'npm' ? name.downcase : name
        key = "#{canon_name}::#{type}"

        packages[key] ||= { 'name' => name, 'type' => type, 'sources' => [], 'dates' => [] }
        p = packages[key]

        src_key = source_info['url'].to_s
        p['sources'] << source_info unless p['sources'].any? { |s| s['url'] == src_key }
        p['dates'] << entry['date'] if entry['date'] && !p['dates'].include?(entry['date'])
      end
    end
  end

  output = packages.values.map do |p|
    dates = p['dates'].compact.sort
    {
      'name'       => p['name'],
      'type'       => p['type'],
      'sources'    => p['sources'].uniq { |s| s['url'] },
      'first_seen' => dates.first,
      'last_seen'  => dates.last
    }
  end.sort_by { |p| [p['type'], p['name'].downcase] }

  puts "\nPackage database:"
  puts "  Unique packages : #{output.size}"
  types = output.group_by { |p| p['type'] }.transform_values(&:size).sort_by { |_, c| -c }
  types.first(8).each { |t, c| puts "    #{t}: #{c}" }

  return if dry_run

  FileUtils.mkdir_p(File.dirname(json_file))

  File.write(json_file, JSON.pretty_generate({
    'generated_at' => Time.now.utc.iso8601,
    'total'        => output.size,
    'packages'     => output
  }))

  CSV.open(csv_file, 'w') do |csv|
    csv << %w[name type sources first_seen last_seen]
    output.each do |pkg|
      csv << [
        pkg['name'],
        pkg['type'],
        JSON.generate(pkg['sources']),
        pkg['first_seen'],
        pkg['last_seen']
      ]
    end
  end

  puts "  JSON : #{json_file}"
  puts "  CSV  : #{csv_file}"
end

# ────────────────────────────────────────────────────────────────────────────
# Load package scrapers
# ────────────────────────────────────────────────────────────────────────────

require_relative 'package_scrapers/ossf'
require_relative 'package_scrapers/socket_dev'
require_relative 'package_scrapers/sonatype'
require_relative 'package_scrapers/checkmarx'
require_relative 'package_scrapers/jfrog'
require_relative 'package_scrapers/snyk'
require_relative 'package_scrapers/aqua_security'
require_relative 'package_scrapers/thehackernews'
require_relative 'package_scrapers/bleepingcomputer'
require_relative 'package_scrapers/talos'
require_relative 'package_scrapers/unit42'
require_relative 'package_scrapers/securelist'
require_relative 'package_scrapers/microsoft_security'
require_relative 'package_scrapers/google_threat_intel'

ALL_PACKAGE_SCRAPERS = {
  'ossf'                => OSSFPackageScraper,
  'socket_dev'          => SocketDevScraper,
  'sonatype'            => SonatypeScraper,
  'checkmarx'           => CheckmarxScraper,
  'jfrog'               => JFrogScraper,
  'snyk'                => SnykScraper,
  'aqua_security'       => AquaSecurityScraper,
  'thehackernews'       => PackageTHNScraper,
  'bleepingcomputer'    => PackageBleepingComputerScraper,
  'talos'               => PackageTalosScraper,
  'unit42'              => PackageUnit42Scraper,
  'securelist'          => PackageSecurelistScraper,
  'microsoft_security'  => PackageMicrosoftSecurityScraper,
  'google_threat_intel' => PackageGoogleThreatIntelScraper,
}.freeze

# ────────────────────────────────────────────────────────────────────────────
# Cache helpers
# ────────────────────────────────────────────────────────────────────────────

def load_package_cache(cache_file)
  return {} unless File.exist?(cache_file)
  data = JSON.parse(File.read(cache_file))
  data.is_a?(Hash) ? data : {}
rescue JSON::ParserError => e
  warn "Warning: package cache corrupt, starting fresh. (#{e.message})"
  {}
end

def print_package_cache_status(cache_file, all_scrapers)
  cache = load_package_cache(cache_file)
  prog  = File.basename($PROGRAM_NAME)

  puts
  puts 'Malicious Package Scraper — Cache Status'
  puts '=' * 78
  puts "Cache : #{File.expand_path(cache_file)}"
  puts

  name_w = 32
  art_w  =  8
  date_w = 12
  pkg_w  =  8

  header = format("%-#{name_w}s  %#{art_w}s  %-#{date_w}s  %-#{date_w}s  %#{pkg_w}s",
                  'Source', 'Articles', 'Earliest', 'Latest', 'Packages')
  puts header
  puts '─' * header.size

  all_scrapers.each do |source_key, klass|
    sc    = cache[source_key] || { 'articles' => {} }
    arts  = sc['articles'] || {}
    dates = arts.values.filter_map { |v| Date.parse(v['date']) rescue nil }
    pkgs  = arts.values.sum { |v| v['packages']&.size.to_i }
    name  = klass::SOURCE_NAME
    name  = name[0, name_w - 1] + '…' if name.length > name_w

    puts format("%-#{name_w}s  %#{art_w}d  %-#{date_w}s  %-#{date_w}s  %#{pkg_w}d",
                name, arts.size, dates.min&.to_s || '—', dates.max&.to_s || '—', pkgs)
  end

  puts '─' * header.size
  puts
  puts "  ruby #{prog}"
  puts "  ruby #{prog} --lookback-days 30"
  puts "  ruby #{prog} --sources ossf,socket_dev"
  puts
end

# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────

options = {
  years:         nil,
  pages_back:    PKG_DEFAULT_PAGES_BACK,
  lookback_days: nil,
  parallel:      PKG_DEFAULT_PARALLEL,
  cache_file:    PKG_CACHE_FILE_DEFAULT,
  json_file:     PKG_JSON_FILE_DEFAULT,
  csv_file:      PKG_CSV_FILE_DEFAULT,
  dry_run:       false,
  sources:       nil,
  skip_sources:  [],
  status:        false,
  read_timeout:  30,
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} [options]"
  opts.separator ''
  opts.separator 'Options:'

  opts.on('-y', '--years N', Integer, "Full scan: go back N years") do |n|
    options[:years] = n
  end

  opts.on('-d', '--lookback-days N', Integer,
          'Incremental: scan N days before last cached article') do |n|
    options[:lookback_days] = n
  end

  opts.on('-b', '--pages-back N', Integer,
          "Incremental overlap pages (default: #{PKG_DEFAULT_PAGES_BACK})") do |n|
    options[:pages_back] = n
  end

  opts.on('-p', '--parallel N', Integer,
          "Parallel workers (default: #{PKG_DEFAULT_PARALLEL})") do |n|
    options[:parallel] = n
  end

  opts.on('-c', '--cache FILE',
          "Cache file (default: scripts/malicious_packages_cache.json)") do |f|
    options[:cache_file] = f
  end

  opts.on('--json FILE', "JSON output (default: malicious_package_database/malicious_packages.json)") do |f|
    options[:json_file] = f
  end

  opts.on('--csv FILE', "CSV output (default: malicious_package_database/malicious_packages.csv)") do |f|
    options[:csv_file] = f
  end

  opts.on('--dry-run', 'Scrape and cache but do not write database') do
    options[:dry_run] = true
  end

  opts.on('--sources KEYS',
          'Comma-separated source keys (default: all). E.g.: ossf,socket_dev,bleepingcomputer') do |v|
    options[:sources] = v.split(',').map(&:strip).map(&:downcase)
  end

  opts.on('--skip-sources KEYS',
          'Comma-separated source keys to exclude (e.g. socket_dev)') do |v|
    options[:skip_sources] = v.split(',').map(&:strip).map(&:downcase)
  end

  opts.on('--status', 'Print cache status table and exit') do
    options[:status] = true
  end

  opts.on('--read-timeout N', Integer,
          'HTTP read timeout in seconds per attempt (default: 30)') do |n|
    options[:read_timeout] = n
  end

  opts.on('-h', '--help', 'Show this help') do
    puts opts
    exit
  end
end.parse!

if options[:status]
  print_package_cache_status(options[:cache_file], ALL_PACKAGE_SCRAPERS)
  exit 0
end

puts 'Malicious Package Scraper'
puts '=' * 60
puts "Cache file   : #{File.expand_path(options[:cache_file])}"
puts "JSON output  : #{File.expand_path(options[:json_file])}"
puts "CSV output   : #{File.expand_path(options[:csv_file])}"
puts "Dry run      : #{options[:dry_run]}"
all_sources_label = "all (#{ALL_PACKAGE_SCRAPERS.keys.join(', ')})"
puts "Sources      : #{options[:sources] ? options[:sources].join(', ') : all_sources_label}"
puts "Skip sources : #{options[:skip_sources].any? ? options[:skip_sources].join(', ') : 'none'}"
puts

full_cache = load_package_cache(options[:cache_file])

scrapers_to_run = if options[:sources]
  ALL_PACKAGE_SCRAPERS.select { |k, _| options[:sources].include?(k) }
else
  ALL_PACKAGE_SCRAPERS
end

if options[:skip_sources].any?
  scrapers_to_run = scrapers_to_run.reject { |k, _| options[:skip_sources].include?(k) }
end

if scrapers_to_run.empty?
  warn "No scrapers to run after applying --sources / --skip-sources filters."
  warn "Available: #{ALL_PACKAGE_SCRAPERS.keys.join(', ')}"
  exit 1
end

total_elapsed = 0.0

scrapers_to_run.each do |source_key, klass|
  source_name = klass::SOURCE_NAME
  puts
  puts "=== Scraping: #{source_name} ==="
  puts

  source_cache = full_cache[source_key] ||= { 'articles' => {}, 'last_updated' => nil }

  # Dummy output_file — package scrapers don't write a blocklist
  dummy_output = File.join(__dir__, '..', 'malicious_package_database', '.pkg_tmp')

  begin
    elapsed = Benchmark.realtime do
      klass.new(
        years:         options[:years],
        pages_back:    options[:pages_back],
        lookback_days: options[:lookback_days],
        parallel:      options[:parallel],
        output_file:   dummy_output,
        cache:         source_cache,
        full_cache:    full_cache,
        cache_file:    options[:cache_file],
        dry_run:       options[:dry_run],
        read_timeout:  options[:read_timeout]
      ).run
    end
    puts "\n#{source_name} completed in #{elapsed.round(2)}s"
    total_elapsed += elapsed
  rescue StandardError => e
    warn "Error scraping #{source_name}: #{e.message}"
    warn e.backtrace.first(5).join("\n") if e.backtrace
  end
end

puts
puts "Total scraping time: #{total_elapsed.round(2)}s"

write_package_database(full_cache, options[:json_file], options[:csv_file],
                       dry_run: options[:dry_run])
