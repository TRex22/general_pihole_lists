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

require 'optparse'
require 'benchmark'
require_relative 'base_scraper'

DEFAULT_PARALLEL   = 20
DEFAULT_PAGES_BACK = 2

CACHE_FILE_DEFAULT  = File.join(__dir__, 'malicious_domains_cache.json')
OUTPUT_FILE_DEFAULT = File.join(__dir__, '..', 'blocklists', 'malicious.txt')

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
require_relative 'scrapers/sophos'
require_relative 'scrapers/checkpoint_research'
require_relative 'scrapers/volexity'
require_relative 'scrapers/sentinelone'
require_relative 'scrapers/elastic_security'
require_relative 'scrapers/zscaler_threatlabz'
require_relative 'scrapers/symantec_threatintel'
require_relative 'scrapers/lumen_blacklotus'
require_relative 'scrapers/red_canary'
require_relative 'scrapers/fortiguard'
require_relative 'scrapers/trendmicro'
require_relative 'scrapers/crowdstrike'
require_relative 'scrapers/huntress'

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
  'sophos'              => SophosScraper,
  'checkpoint_research'  => CheckpointResearchScraper,
  'volexity'             => VolexityScraper,
  'sentinelone'          => SentinelOneScraper,
  'elastic_security'     => ElasticSecurityScraper,
  'zscaler_threatlabz'   => ZscalerThreatLabzScraper,
  'symantec_threatintel' => SymantecThreatIntelScraper,
  'lumen_blacklotus'     => LumenBlackLotusLabsScraper,
  'red_canary'           => RedCanaryScraper,
  'fortiguard'           => FortiguardScraper,
  'trendmicro'           => TrendMicroScraper,
  'crowdstrike'          => CrowdStrikeScraper,
  'huntress'             => HuntressScraper,
}.freeze

# ────────────────────────────────────────────────────────────────────────────
# Cache status report
# ────────────────────────────────────────────────────────────────────────────

def print_cache_status(cache_file, all_scrapers)
  cache = load_full_cache(cache_file)
  prog  = File.basename($PROGRAM_NAME)

  puts
  puts 'Malicious Domain Scraper — Cache Status'
  puts '=' * 78
  puts "Cache : #{File.expand_path(cache_file)}"
  puts

  name_w = 28
  art_w  =  8
  date_w = 12
  dom_w  =  8

  header = format("%-#{name_w}s  %#{art_w}s  %-#{date_w}s  %-#{date_w}s  %#{dom_w}s",
                  'Source', 'Articles', 'Earliest', 'Latest', 'Domains')
  divider = '─' * header.size

  puts header
  puts divider

  all_scrapers.each do |source_key, klass|
    source_cache = cache[source_key] || { 'articles' => {} }
    real         = (source_cache['articles'] || {}).reject { |_, v| v['skipped_too_old'] }
    dates        = real.values.filter_map { |v| Date.parse(v['date']) rescue nil }

    count    = real.size
    earliest = dates.min&.to_s || '—'
    latest   = dates.max&.to_s || '—'
    domains  = real.values.sum { |v| v['domains']&.size.to_i }
    name     = klass::SOURCE_NAME
    name     = name[0, name_w - 1] + '…' if name.length > name_w

    puts format("%-#{name_w}s  %#{art_w}d  %-#{date_w}s  %-#{date_w}s  %#{dom_w}d",
                name, count, earliest, latest, domains)
  end

  puts divider

  all_dates = all_scrapers.flat_map do |source_key, _|
    ((cache[source_key] || {})['articles'] || {})
      .reject { |_, v| v['skipped_too_old'] }
      .values.filter_map { |v| Date.parse(v['date']) rescue nil }
  end
  oldest      = all_dates.min
  years_back  = oldest ? [Date.today.year - oldest.year + 1, DEFAULT_YEARS].max : DEFAULT_YEARS
  source_keys = all_scrapers.keys

  puts
  puts 'Example commands'
  puts '─' * 50
  puts
  puts '  Re-run incrementally (new articles since last cached date):'
  puts "    ruby #{prog}"
  puts
  puts '  Extend lookback window (N days before last cached date):'
  puts "    ruby #{prog} --lookback-days 30"
  puts "    ruby #{prog} --lookback-days 90"
  puts
  puts '  Full scan going further back in time:'
  puts "    ruby #{prog} --years #{years_back + 1}"
  puts "    ruby #{prog} --years #{years_back + 2}"
  puts
  puts '  Scan a single source:'
  puts "    ruby #{prog} --sources #{source_keys.first}"
  puts "    ruby #{prog} --sources #{source_keys.first} --years #{years_back + 1}"
  puts
  puts '  Scan multiple specific sources:'
  puts "    ruby #{prog} --sources #{source_keys.first(3).join(',')}"
  puts
end

# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────

options = {
  years:          nil,
  pages_back:     DEFAULT_PAGES_BACK,
  lookback_days:  nil,
  parallel:       DEFAULT_PARALLEL,
  output_file:    OUTPUT_FILE_DEFAULT,
  cache_file:     CACHE_FILE_DEFAULT,
  dry_run:        false,
  rescan_images:  false,
  browser_fetch:  false,
  skip_ocr:       false,
  ocr_only:       false,
  ignore_cache:   false,
  sources:        nil,
  skip_sources:   [],
  status:         false,
  read_timeout:   30,
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
          'Incremental mode: also scan N days before the last cached article') do |n|
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

  opts.on('--dry-run', 'Scrape and cache but do not write to blocklist') do
    options[:dry_run] = true
  end

  opts.on('--rescan-images',
          'Re-OCR images in cached articles not yet processed') do
    options[:rescan_images] = true
  end

  opts.on('--browser-fetch',
          'Use Safari (macOS only) to fetch Cloudflare-protected pages') do
    options[:browser_fetch] = true
  end

  opts.on('--skip-ocr', 'Cache image URLs but skip OCR') do
    options[:skip_ocr] = true
  end

  opts.on('--ocr-only',
          'Skip article scraping; re-fetch images and re-run OCR on cached articles') do
    options[:ocr_only] = true
  end

  opts.on('--ignore-cache',
          'Re-fetch every article even if already cached (cache is still updated)') do
    options[:ignore_cache] = true
  end

  opts.on('--sources KEYS',
          'Comma-separated source keys to scrape (default: all)') do |v|
    options[:sources] = v.split(',').map(&:strip).map(&:downcase)
  end

  opts.on('--skip-sources KEYS',
          'Comma-separated source keys to exclude (e.g. trendmicro,sophos)') do |v|
    options[:skip_sources] = v.split(',').map(&:strip).map(&:downcase)
  end

  opts.on('--status',
          'Print a table of cached article date ranges per source, then exit') do
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
  print_cache_status(options[:cache_file], ALL_SCRAPERS)
  exit 0
end

puts 'Malicious Domain Scraper'
puts '=' * 60
puts "Output file  : #{File.expand_path(options[:output_file])}"
puts "Cache file   : #{File.expand_path(options[:cache_file])}"
puts "Dry run      : #{options[:dry_run]}"
puts "Ignore cache : #{options[:ignore_cache]}"
all_sources_label = "all (#{ALL_SCRAPERS.keys.join(', ')})"
puts "Sources      : #{options[:sources] ? options[:sources].join(', ') : all_sources_label}"
puts "Skip sources : #{options[:skip_sources].any? ? options[:skip_sources].join(', ') : 'none'}"
puts "OCR backend  : #{options[:skip_ocr] ? 'skipped (--skip-ocr)' : (BaseScraper.ocr_backend || 'none')}"
puts

# Load allowlists and apply Blocklist Project category filter
REPO_ROOT = File.expand_path('..', __dir__).freeze
_allowlist_raw = Set.new.tap do |domains|
  paths = Dir.glob(File.join(REPO_ROOT, 'allowlists', '*.txt')) + [
    File.join(REPO_ROOT, 'blocklists', 'ublock', 'allowlist.txt'),
  ]
  paths.each do |path|
    next unless File.exist?(path)
    File.foreach(path) do |line|
      line = line.strip
      next if line.empty? || line.start_with?('#')
      domain = line.split('#').first.strip.downcase
      domains << domain unless domain.empty?
    end
  end
end
puts "Allowlists  : #{_allowlist_raw.size} domains loaded (manual + ublock)"
_blp         = load_blocklist_project_domains
_blp_removed = _allowlist_raw & _blp
_allowlist_raw.subtract(_blp_removed)
if _blp_removed.any?
  puts "Blocklist Project filter: removed #{_blp_removed.size} domain(s) from allowlist:"
  _blp_removed.to_a.sort.each { |d| puts "  - #{d}" }
else
  puts "Blocklist Project filter: no domains removed from allowlist"
end
ALLOWLIST_DOMAINS = _allowlist_raw.freeze
puts

full_cache = load_full_cache(options[:cache_file])

scrapers_to_run = if options[:sources]
  ALL_SCRAPERS.select { |k, _| options[:sources].include?(k) }
else
  ALL_SCRAPERS
end

if options[:skip_sources].any?
  scrapers_to_run = scrapers_to_run.reject { |k, _| options[:skip_sources].include?(k) }
end

if scrapers_to_run.empty?
  warn "No scrapers to run after applying --sources / --skip-sources filters."
  warn "Available: #{ALL_SCRAPERS.keys.join(', ')}"
  exit 1
end

total_elapsed = 0.0

scrapers_to_run.each do |source_key, klass|
  source_name = klass::SOURCE_NAME
  puts
  puts "=== Scraping: #{source_name} ==="
  puts

  source_cache = full_cache[source_key] ||= { 'articles' => {}, 'last_updated' => nil }

  begin
    elapsed = Benchmark.realtime do
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
        ocr_only:      options[:ocr_only],
        ignore_cache:  options[:ignore_cache],
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
