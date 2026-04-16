# frozen_string_literal: true

# Shared helper: downloads Blocklist Project category lists and returns a Set
# of domains to exclude from allowlists.
#
# Lists are cached locally for CACHE_TTL_DAYS to avoid re-downloading on every run.
# Cache file: scripts/blocklist_project_cache.json
#
# Categories used: adult (porn), gambling, fraud, malware, phishing,
#                  piracy, scam, drugs, ads

require 'net/http'
require 'uri'
require 'json'
require 'set'
require 'time'

BLOCKLIST_PROJECT_CACHE_FILE = File.join(__dir__, 'blocklist_project_cache.json').freeze
BLOCKLIST_PROJECT_CACHE_TTL_DAYS = 1

ADULT_TLDS = Set.new(%w[xxx adult porn sex]).freeze

# TLDs that are unambiguously file extensions in practice.
# Includes .py (Paraguay) and .sh (Saint Helena) because virtually every
# occurrence in filter lists and security articles is a script filename,
# not a real registered domain. Legitimate domains under these ccTLDs are
# vanishingly rare and would need explicit allowlist entries anyway.
FILE_EXTENSION_TLDS = Set.new(%w[
  exe dll sys drv bat cmd ps1 vbs scr pif lnk
  rar gz tar 7z bz2 xz cab iso img dmg pkg deb rpm apk ipa
  txt log ini cfg dat
  doc docx xls xlsx ppt pptx pdf
  mp3 mp4 avi mkv flv wav
  php asp aspx jsp
  png jpg jpeg gif bmp webp ico tiff
  rb py sh go cpp java class jar
]).freeze

# NL (no-list) variants are plain domain lists — simpler to parse than hosts format.
BLOCKLIST_PROJECT_LISTS = {
  'adult'    => 'https://blocklistproject.github.io/Lists/alt-version/porn-nl.txt',
  'gambling' => 'https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt',
  'fraud'    => 'https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt',
  'malware'  => 'https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt',
  'phishing' => 'https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt',
  'piracy'   => 'https://blocklistproject.github.io/Lists/alt-version/piracy-nl.txt',
  'scam'     => 'https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt',
  'drugs'    => 'https://blocklistproject.github.io/Lists/alt-version/drugs-nl.txt',
  'ads'      => 'https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt',
}.freeze

def _blp_fetch_url(url)
  uri = URI.parse(url)
  response = Net::HTTP.get_response(uri)
  case response
  when Net::HTTPSuccess    then response.body
  when Net::HTTPRedirection then _blp_fetch_url(response['location'])
  else
    warn "  HTTP #{response.code} fetching #{url}"
    nil
  end
rescue StandardError => e
  warn "  Error fetching #{url}: #{e.message}"
  nil
end

# Returns a frozen Set of all domains across all Blocklist Project categories.
# Uses a local JSON cache; re-downloads when the cache is older than CACHE_TTL_DAYS.
def load_blocklist_project_domains
  if File.exist?(BLOCKLIST_PROJECT_CACHE_FILE)
    cached      = JSON.parse(File.read(BLOCKLIST_PROJECT_CACHE_FILE))
    fetched_at  = Time.parse(cached['fetched_at']) rescue nil
    age_days    = fetched_at ? (Time.now - fetched_at) / 86_400.0 : Float::INFINITY

    if age_days < BLOCKLIST_PROJECT_CACHE_TTL_DAYS
      puts "Blocklist Project: #{cached['domains'].size} cached domains " \
           "(fetched #{fetched_at.strftime('%Y-%m-%d')}, " \
           "refresh in #{(BLOCKLIST_PROJECT_CACHE_TTL_DAYS - age_days).ceil}d)"
      return Set.new(cached['domains']).freeze
    end
  end

  puts "Fetching Blocklist Project category lists..."
  domains = Set.new

  BLOCKLIST_PROJECT_LISTS.each do |category, url|
    print "  %-10s " % "#{category}..."
    content = _blp_fetch_url(url)
    unless content
      puts "FAILED"
      next
    end
    count_before = domains.size
    content.each_line do |line|
      line = line.strip
      next if line.empty? || line.start_with?('#')
      domain = line.split('#').first.strip.downcase
      domains << domain unless domain.empty?
    end
    puts "+#{domains.size - count_before}"
  end

  File.write(BLOCKLIST_PROJECT_CACHE_FILE, JSON.generate(
    'fetched_at' => Time.now.utc.iso8601,
    'domains'    => domains.to_a.sort
  ))

  puts "Blocklist Project: #{domains.size} total domains cached to #{BLOCKLIST_PROJECT_CACHE_FILE}"
  domains.freeze
end

# Loads all *.txt files from the repo's allowlists/ directory.
# Returns a frozen Set of domains that should never appear in a blocklist.
def load_repo_allowlists(repo_root)
  domains = Set.new
  Dir.glob(File.join(repo_root, 'allowlists', '*.txt')).each do |path|
    File.foreach(path) do |line|
      line = line.strip
      next if line.empty? || line.start_with?('#')
      domain = line.split('#').first.strip.downcase
      domains << domain unless domain.empty?
    end
  end
  domains.freeze
end

# Removes Blocklist Project domains from +allowlist_set+ (a Set) in place.
# Prints each removed domain. Returns the count of removed domains.
def filter_allowlist_with_blocklist_project!(allowlist_set)
  blocked = load_blocklist_project_domains
  removed = allowlist_set & blocked
  allowlist_set.subtract(removed)
  if removed.any?
    puts "Blocklist Project filter: removed #{removed.size} domain(s) from allowlist:"
    removed.to_a.sort.each { |d| puts "  - #{d}" }
  else
    puts "Blocklist Project filter: no domains removed from allowlist"
  end
  removed.size
end
