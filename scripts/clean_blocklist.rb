#!/usr/bin/env ruby
# frozen_string_literal: true

# Standalone Blocklist Cleaner
#
# Runs the same skip-list / Blocklist-Project / validity filtering that
# scrape_malicious_domains.rb applies automatically at the end of every run
# (BaseScraper#clean_blocklist), without doing any scraping. Useful when
# SKIP_DOMAINS, EXACT_SKIP_DOMAINS, or the allowlists have changed and you
# want blocklists/malicious.txt re-cleaned without a full (slow,
# network-heavy) scrape.
#
# Usage:
#   ruby scripts/clean_blocklist.rb
#   ruby scripts/clean_blocklist.rb --file blocklists/malicious.txt
#   ruby scripts/clean_blocklist.rb --dry-run

require 'optparse'
require 'tempfile'
require_relative 'base_scraper'

REPO_ROOT    = File.expand_path('..', __dir__).freeze
DEFAULT_FILE = File.join(REPO_ROOT, 'blocklists', 'malicious.txt')

options = {
  file:    DEFAULT_FILE,
  dry_run: false,
}

OptionParser.new do |opts|
  opts.banner = "Usage: #{$PROGRAM_NAME} [options]"
  opts.on('--file PATH', "Blocklist file to clean (default: #{DEFAULT_FILE})") { |v| options[:file] = File.expand_path(v) }
  opts.on('--dry-run', 'Report what would be removed without writing') { options[:dry_run] = true }
end.parse!

unless File.exist?(options[:file])
  warn "File not found: #{options[:file]}"
  exit 1
end

# ── Load allowlists and apply Blocklist Project category filter ───────────────
# Identical setup to scrape_malicious_domains.rb, so skip_domain? makes
# exactly the same decisions here as it would during a live scrape.
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

puts 'Blocklist Cleaner'
puts '=' * 60
puts "File    : #{options[:file]}"
puts "Dry run : #{options[:dry_run]}"
puts

# clean_blocklist (BaseScraper, private) only needs @output_file — allocate
# skips the full scraper constructor (cache/network setup we don't need here).
def run_clean_blocklist(target_file)
  cleaner = StandardPaginatedScraper.allocate
  cleaner.instance_variable_set(:@output_file, target_file)
  cleaner.send(:clean_blocklist)
end

if options[:dry_run]
  tempfile = Tempfile.new(['clean_blocklist_dryrun', '.txt'])
  begin
    tempfile.write(File.read(options[:file]))
    tempfile.close

    original_stdout = $stdout
    $stdout = StringIO.new
    run_clean_blocklist(tempfile.path)
    $stdout = original_stdout

    before = File.readlines(options[:file], chomp: true)
                 .map { |l| l.strip.split('#').first&.strip&.downcase }
                 .reject { |l| l.nil? || l.empty? }.to_set
    after  = File.readlines(tempfile.path, chomp: true)
                 .map { |l| l.strip.split('#').first&.strip&.downcase }
                 .reject { |l| l.nil? || l.empty? }.to_set
    removed = (before - after).to_a.sort

    if removed.any?
      puts "[DRY RUN] Would remove #{removed.size} domain(s):"
      removed.each { |d| puts "  - #{d}" }
    else
      puts '[DRY RUN] Nothing to remove.'
    end
  ensure
    tempfile.close unless tempfile.closed?
    tempfile.unlink
  end
else
  run_clean_blocklist(options[:file])
  puts 'Done.'
end
