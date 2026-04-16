# frozen_string_literal: true

# Shared helper: downloads Blocklist Project category lists and returns a Set
# of domains to exclude from allowlists.
#
# Also defines shared domain-skip constants (SKIP_DOMAINS, EXACT_SKIP_DOMAINS,
# SKIP_IPS) used by all three generation scripts as a single source of truth.
# A top-level skip_domain_static?(domain) helper is provided so the extract
# scripts can call it without duplicating the logic.
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

# ────────────────────────────────────────────────────────────────────────────
# Shared domain-skip constants
#
# These are used by scrape_malicious_domains.rb, extract_ublock_lists.rb, and
# extract_privacy_badger_lists.rb as a single authoritative source of truth.
# Update here and all three scripts pick up the change automatically.
# ────────────────────────────────────────────────────────────────────────────

# Domains (and their subdomains) that are never themselves malicious — they
# appear in security articles as attack targets, platforms, reference links,
# or are well-known legitimate services that broad blocklists incorrectly flag.
# Subdomain cascade: "api.youtube.com" matches "youtube.com" in this list.
SKIP_DOMAINS = Set.new(%w[
  youtube.com youtu.be
  twitter.com x.com t.co
  facebook.com instagram.com linkedin.com
  whatsapp.com whatsapp.net wa.me
  reddit.com
  telegram.org t.me api.telegram.org telegram.me
  discord.com discord.gg discordapp.com discordapp.net
  tiktok.com tiktokv.com tiktokcdn.com tiktokcdn-us.com musical.ly snssdk.com bytedance.com
  google.com gmail.com googleapis.com gstatic.com googletagmanager.com
  googleusercontent.com app.google drive.google.com
  google.ca google.co.in google.co.uk google.de google.fr google.co.jp
  appsheet.com
  microsoft.com outlook.com office.com office365.com visualstudio.com
  login.windows.net office.net
  windows.com windowsupdate.com windowsazure.com
  live.com hotmail.com bing.com
  microsoftonline.com login.microsoftonline.com
  azure.com azuredatabricks.net azurehdinsight.net
  msidentity.com microsoftidentity.com
  apple.com icloud.com
  amazon.com amazon.pl amazonaws.com
  cloudflare.com bootcdn.net bootcss.com
  github.com githubusercontent.com github.dev
  gitlab.com bitbucket.org
  wikipedia.org wikimedia.org
  apache.org
  asp.net
  thehackernews.com
  virustotal.com shodan.io censys.io urlscan.io
  hybrid-analysis.com any.run
  abuse.ch threatfox.abuse.ch urlhaus.abuse.ch bazaar.abuse.ch
  talosintelligence.com snort.org
  cisco.com
  mitre.org cve.mitre.org
  nvd.nist.gov nist.gov cisa.gov
  bleepingcomputer.com krebsonsecurity.com
  darkreading.com securityweek.com threatpost.com
  techcrunch.com wired.com arstechnica.com zdnet.com
  reuters.com bbc.com bbc.co.uk cnn.com
  dw.com
  prnewswire.com
  americanexpress.com
  baidu.com baidu.cn
  oracle.com salesforce.com adobe.com sap.com
  paypal.com stripe.com
  wordpress.com wordpress.org
  php.net python.org ruby-lang.org nodejs.org
  npmjs.com registry.npmjs.org pypi.org rubygems.org
  stackoverflow.com stackexchange.com
  docker.com kubernetes.io
  debian.org ubuntu.com redhat.com
  protonmail.com proton.me proofpoint.com
  icann.org okta.com okta.net oktacdn.com twilio.com docusign.com docusign.net
  chatgpt.com claude.ai deepseek.com deepseek.ai huggingface.co
  grok.com x.ai xai.com
  kaspersky.com kaspersky.ru kaspersky.net securelist.com
  zoom.us zoom.com zoomgov.com zoomus.cn zoom.video zmvideo.com
  semgrep.dev cursor.com cursor.sh cursor.so
  blogspot.com archive.org
  7-zip.org brew.sh example.com
  dropbox.com dropboxstatic.com
  isc.sans.edu sans.org sans.edu
  polyfill.io polyfill.com
  letsencrypt.org digicert.com sectigo.com comodo.com ssl.com usertrust.com
  globalsign.com globalsign.net
  etherscan.io binance.com metamask.io coinbasepro.com localbitcoins.com
  ip-api.com ipapi.co ipinfo.io ipgeolocation.io ifconfig.me
  matrix.org meta.com msn.com vk.com trello.com
  mail.ru rambler.ru ukr.net
  notepad-plus-plus.org open-vsx.org pkg.go.dev unpkg.com vscode.dev
  dictionary.com indeed.com zohomail.com zoho.com zendesk.com
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
  jsdelivr.net cdnjs.cloudflare.com cdnjs.com
  pastebin.com paste.ee
  shodan.io
  msftconnecttest.com www.msftconnecttest.com
  yahoo.com yahoo.co.uk
  herokuapp.com
  nslookup.io
  ngrok.com
  booking.com
  jquery.com
  crates.io
  crazygames.com
  domain.com
  eset.com eset.sk eset.eu
  ford.com fordvehicles.com lincolnvehicles.com
  freshdesk.com freshworks.com freshservice.com freshchat.com freshcaller.com
  githubassets.com
  who.is whois.com domaintools.com iana.org
  mailchimp.com list-manage.com mandrillapp.com
  postmarkapp.com mtasv.net
  mailjet.com
  medium.com
  zimbra.com zextras.com synacor.com
  akamai.com fastly.com keycdn.com cloudinary.com
  yandex.com yandex.ru
  fast.com
  fasterxml.org
  mail.com
  hp.com
  chase.com
  schwab.com usbank.com
  synchronybank.com synchronyfinancial.com
  europa.eu
  horizon3ai.com
  understandingwar.org
  zone-h.org
  olemiss.edu
  hotjarcdn.com
  mailmeteor.com
  nifty.com
  newrelic.com datadoghq.com sentry.io dynatrace.com loggly.com
  riotgames.com
  kaltura.com
  opera.com
  mercadolibre.com
]).freeze

# Root-level cloud/CDN platform domains that are too broad to block wholesale —
# only the bare root is skipped; specific malicious subdomains remain blockable.
EXACT_SKIP_DOMAINS = Set.new(%w[
  azureedge.net
  azurefd.net
  windows.net
  azurewebsites.net
  cloudapp.net
  cloudapp.azure.com
  trafficmanager.net
  servicebus.windows.net
  database.windows.net
  blob.core.windows.net
  table.core.windows.net
  queue.core.windows.net
  file.core.windows.net
  vault.azure.net
  search.windows.net
  workers.dev
  cloudfunctions.net
  netlify.app
  netlify.com
  vercel.app
  pages.dev
  github.io
  ngrok.io
  tcp.ngrok.io
  ngrok-free.app
  ngrok.app
  fastly.net
  akamaihd.net
  akamaized.net
  cloudfront.net
  cdn77.com
  stackpath.com
  stackpathcdn.com
  bunnycdn.com
  b-cdn.net
]).freeze

# Known-safe IP addresses (public DNS resolvers, CDN anycast, loopback)
SKIP_IPS = Set.new(%w[
  8.8.8.8 8.8.4.4
  1.1.1.1 1.0.0.1
  9.9.9.9 149.112.112.112
  208.67.222.222 208.67.220.220
  0.0.0.0 127.0.0.1
]).freeze

# Returns true if +domain+ should be excluded from any generated blocklist.
# Checks SKIP_IPS, EXACT_SKIP_DOMAINS (exact match), and SKIP_DOMAINS
# (subdomain cascade). Does NOT check the runtime ALLOWLIST_DOMAINS that
# scrape_malicious_domains.rb loads from allowlist files — that lives in
# BaseScraper#skip_domain? alongside this call.
def skip_domain_static?(domain)
  return false if domain.nil? || domain.empty?
  return true if SKIP_IPS.include?(domain)
  return true if EXACT_SKIP_DOMAINS.include?(domain)
  SKIP_DOMAINS.any? { |s| domain == s || domain.end_with?(".#{s}") }
end

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
