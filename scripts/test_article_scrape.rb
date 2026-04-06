#!/usr/bin/env ruby
# frozen_string_literal: true
# One-shot test: fetch a single THN article via the Blogger feed, extract
# images (with optional Safari browser fetch), run OCR, find domains.
#
# Usage:
#   ruby scripts/test_article_scrape.rb [article-url] [--browser-fetch]
#
# --browser-fetch : open article in Safari (bypasses Cloudflare) to extract images
# Default URL is the LiteLLM article used to validate the pipeline.

require 'httparty'
require 'nokogiri'
require 'uri'
require 'set'
require 'tempfile'
require 'json'

TARGET_URL     = (ARGV.reject { |a| a.start_with?('-') }.first ||
                  'https://thehackernews.com/2026/04/how-litellm-turned-developer-machines.html').freeze
BROWSER_FETCH  = ARGV.include?('--browser-fetch')
FEED_BASE_URL  = 'https://thehackernews.com/feeds/posts/default'

VALID_DOMAIN_RE = /\A(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\z/

SKIP_DOMAINS = Set.new(%w[
  youtube.com youtu.be twitter.com x.com facebook.com instagram.com linkedin.com
  reddit.com telegram.org discord.com google.com gmail.com googleapis.com
  gstatic.com googletagmanager.com googleusercontent.com microsoft.com
  outlook.com office.com apple.com icloud.com amazon.com cloudflare.com
  github.com githubusercontent.com wikipedia.org wikimedia.org apache.org
  thehackernews.com virustotal.com shodan.io censys.io urlscan.io
  hybrid-analysis.com any.run abuse.ch talosintelligence.com mitre.org
  nvd.nist.gov nist.gov cisa.gov bleepingcomputer.com krebsonsecurity.com
  techcrunch.com wired.com arstechnica.com zdnet.com reuters.com bbc.com
  oracle.com paypal.com stripe.com wordpress.com docker.com debian.org
  ubuntu.com protonmail.com proton.me chatgpt.com claude.ai blogspot.com
  archive.org example.com npmjs.com pypi.org rubygems.org stackoverflow.com
]).freeze

EXACT_SKIP_DOMAINS = Set.new(%w[
  azureedge.net azurefd.net windows.net workers.dev cloudfunctions.net
]).freeze

IMAGE_SKIP_FRAGMENTS = %w[
  doubleclick.net googlesyndication.com adserv advert
  /pixel. /1x1. /tracking /beacon /analytics /stat.
  /social/ /share-button /twitter-bird /fb-button /whatsapp
  /favicon /apple-touch-icon /touch-icon
  gravatar.com /avatar/ /author- /author_
  /logo. /badge. /icon-
  feeds.feedburner.com
].freeze

OCR_MACOS_SCRIPT = File.join(__dir__, 'ocr_macos.swift')
OCR_MACOS_BINARY = File.join(__dir__, 'ocr_macos')

# ── helpers ──────────────────────────────────────────────────────────────────

def hr(char = '─', width = 60) = puts(char * width)

def normalize_domain(raw)
  raw.gsub('[.]', '.').gsub(/\/.*\z/, '').gsub(/#.*\z/, '').chomp('.').downcase.strip
end

def valid_domain?(d)
  return false if d.nil? || d.empty? || d.length > 253
  return false if d.include?('*') || d.include?(':') || d.include?('/') || d == 'localhost'
  return false if /\A\d+\.\d+\.\d+\.\d+\z/.match?(d)
  return false unless d.include?('.')
  VALID_DOMAIN_RE.match?(d)
end

def skip_domain?(d)
  return false if d.nil? || d.empty?
  return true if EXACT_SKIP_DOMAINS.include?(d)
  SKIP_DOMAINS.any? { |s| d == s || d.end_with?(".#{s}") }
end

def scan_text_for_domains(text, domains)
  text.scan(/[a-zA-Z0-9][a-zA-Z0-9.\-]*\[\.\][a-zA-Z0-9.\-]*[a-zA-Z0-9]/) do |m|
    c = normalize_domain(m)
    domains << c if valid_domain?(c) && !skip_domain?(c)
  end
end

def cloudflare_challenge?(html)
  html.include?('Enable JavaScript and cookies to continue') ||
    html.include?('_cf_chl_opt') ||
    html.include?('cf-browser-verification')
end

def article_content(doc)
  doc.at_css('.articlebody, .article-body, .post-body, #articlebody, article .entry-content, main') ||
    doc.at_css('body')
end

def extract_images(doc, base_url)
  content = article_content(doc)
  return [] unless content

  base_uri = URI.parse(base_url)
  seen = Set.new
  images = []

  content.css('img').each do |img|
    src = nil
    %w[src data-src data-lazy-src data-original data-lazy].each do |attr|
      val = img[attr]&.strip
      next if val.nil? || val.empty? || val.start_with?('data:')
      src = val
      break
    end
    if src.nil?
      src = img['srcset']&.split(/[\s,]+/)&.find { |s| !s.start_with?('data:') && s.include?('.') }
    end

    next if src.nil? || src.strip.empty?

    url = begin
      URI.join(base_uri, src).to_s
    rescue URI::Error
      src.start_with?('http') ? src : nil
    end

    next unless url&.start_with?('http')
    next if IMAGE_SKIP_FRAGMENTS.any? { |f| url.downcase.include?(f) }

    w = img['width']&.to_i
    h = img['height']&.to_i
    next if (w && w.positive? && w < 50) || (h && h.positive? && h < 50)

    next unless seen.add?(url)
    images << url
  end

  images
end

def detect_ocr_backend
  if RUBY_PLATFORM.include?('darwin') && File.exist?(OCR_MACOS_SCRIPT)
    swift_ok = system('which swiftc > /dev/null 2>&1') || system('which swift > /dev/null 2>&1')
    return :macos if swift_ok
  end
  return :tesseract if system('which tesseract > /dev/null 2>&1')
  nil
end

def ocr_backend
  @ocr_backend ||= detect_ocr_backend
end

def ensure_macos_ocr_compiled
  return if File.exist?(OCR_MACOS_BINARY)
  puts 'Compiling macOS OCR helper...'
  unless system('swiftc', OCR_MACOS_SCRIPT, '-o', OCR_MACOS_BINARY)
    puts 'Compilation failed — will skip OCR'
    @ocr_backend = nil
  end
end

def image_extension_from(url, content_type)
  case content_type&.split(';')&.first&.strip
  when 'image/png'  then '.png'
  when 'image/jpeg' then '.jpg'
  when 'image/gif'  then '.gif'
  when 'image/webp' then '.webp'
  else url.match(/\.(png|jpe?g|gif|webp|bmp)/i)&.[](0) || '.jpg'
  end
end

def ocr_image(image_url)
  return nil unless ocr_backend
  ensure_macos_ocr_compiled if ocr_backend == :macos

  response = HTTParty.get(
    image_url,
    headers: { 'User-Agent' => 'Mozilla/5.0 (compatible; pihole-list-builder/1.0)' },
    timeout: 30,
    follow_redirects: true
  )
  return nil unless response.success?

  ext = image_extension_from(image_url, response.headers['content-type'])

  Tempfile.create(['ocr_test', ext]) do |tmp|
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
  puts "  OCR error: #{e.message}"
  nil
end

def fetch_json(url)
  HTTParty.get(
    url,
    headers: {
      'User-Agent' => 'Mozilla/5.0 (compatible; pihole-list-builder/1.0)',
      'Accept'     => 'application/json'
    },
    timeout: 30,
    follow_redirects: true
  )
end

# Open the URL in Safari via AppleScript, wait for JS to run (handles Cloudflare),
# return the rendered page source. Returns nil on any error.
def fetch_via_browser(url, wait_seconds: 5)
  unless RUBY_PLATFORM.include?('darwin') && system('which osascript > /dev/null 2>&1')
    puts '  Browser fetch not available (requires macOS + osascript)'
    return nil
  end

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

  puts "  Opening in Safari (wait #{wait_seconds}s for page to render)..."
  result = IO.popen(['osascript', '-e', script], err: File::NULL, &:read)
  if $?.success? && !result.strip.empty?
    puts "  Browser fetch: #{result.bytesize} bytes"
    result
  else
    puts '  Browser fetch failed (osascript returned empty or error)'
    nil
  end
rescue StandardError => e
  puts "  Browser fetch error: #{e.message}"
  nil
end

# ── 1. Fetch article HTML (direct HTTP first) ────────────────────────────────

puts
hr('═')
puts "Test: image extraction + OCR domain scraping"
puts "URL : #{TARGET_URL}"
puts "Browser fetch: #{BROWSER_FETCH ? 'enabled' : 'disabled (pass --browser-fetch to enable)'}"
hr('═')
puts "\nOCR backend: #{ocr_backend || 'NONE — install tesseract or run on macOS with swiftc'}"

def fetch_direct(url)
  HTTParty.get(
    url,
    headers: {
      'User-Agent' => 'Mozilla/5.0 (compatible; pihole-list-builder/1.0)',
      'Accept'     => 'text/html,application/xhtml+xml,*/*;q=0.8'
    },
    timeout: 30,
    follow_redirects: true
  )
rescue StandardError => e
  puts "  Direct fetch error: #{e.message}"
  nil
end

hr
puts "Step 1: direct HTTP fetch of article..."
direct_resp = fetch_direct(TARGET_URL)
article_html = nil
if direct_resp&.success? && !cloudflare_challenge?(direct_resp.body)
  article_html = direct_resp.body
  puts "  Success: #{article_html.bytesize} bytes"
elsif direct_resp
  puts "  Cloudflare challenge or HTTP #{direct_resp.code} — will try feed + browser fallback"
else
  puts "  Request failed"
end

# ── 2. Feed summary as fallback for text domain extraction ───────────────────

feed_summary  = nil
article_title = nil

if article_html.nil? || article_html.strip.empty?
  hr
  puts "Step 2: fetching feed summary (text domains only)..."

  target_variants = [TARGET_URL, TARGET_URL.sub(/^https?/, 'http'), TARGET_URL.sub(/^https?/, 'https')]
  feed_url = "#{FEED_BASE_URL}?max-results=25&alt=json"
  page     = 1

  loop do
    puts "  Feed page #{page}: #{feed_url}"
    resp = fetch_json(feed_url)
    unless resp.success?
      puts "  Feed fetch failed: HTTP #{resp.code}"
      break
    end

    data    = JSON.parse(resp.body)
    entries = data.dig('feed', 'entry') || []
    break if entries.empty?

    found = entries.find do |e|
      href = e['link']&.find { |l| l['rel'] == 'alternate' }&.dig('href')
      target_variants.include?(href)
    end

    if found
      feed_summary  = found.dig('content', '$t') || found.dig('summary', '$t')
      article_title = found.dig('title', '$t')&.strip
      puts "  Found: \"#{article_title}\" (#{feed_summary&.bytesize || 0} bytes — summary only)"
      break
    end

    next_link = data.dig('feed', 'link')&.find { |l| l['rel'] == 'next' }&.dig('href')
    break unless next_link

    feed_url = next_link
    page += 1
    sleep 0.5
  end
end

# ── 3. Parse for text domains and images ─────────────────────────────────────

hr
puts "Step 3: parsing HTML for text domains and images..."

parse_html = article_html || feed_summary.to_s
doc        = Nokogiri::HTML(parse_html)
content    = article_content(doc)
puts "  Source       : #{article_html ? 'direct HTTP fetch' : 'feed summary'}"
puts "  Content node : <#{content&.name}#{" class=#{content['class'].inspect}" if content&.[]('class')}>"
puts "  Text length  : #{content&.text&.length || 0} chars"

text_domains = Set.new
scan_text_for_domains(content&.text.to_s, text_domains)
if text_domains.any?
  text_domains.sort.each { |d| puts "  [TEXT] #{d}" }
else
  puts "  Text domains: (none found)"
end

images = article_html ? extract_images(doc, TARGET_URL) : []
puts "  Images found : #{images.size}"

# ── 4. Browser fetch fallback for images (if direct fetch was blocked) ───────

if images.empty? && BROWSER_FETCH
  hr
  puts "Step 4: Safari browser fetch (Cloudflare bypass)..."
  browser_html = fetch_via_browser(TARGET_URL)
  if browser_html && !cloudflare_challenge?(browser_html)
    browser_doc = Nokogiri::HTML(browser_html)
    images      = extract_images(browser_doc, TARGET_URL)
    puts "  Images from browser fetch: #{images.size}"
    browser_content = article_content(browser_doc)
    scan_text_for_domains(browser_content&.text.to_s, text_domains)
  elsif browser_html
    puts "  Browser fetch returned a Cloudflare challenge"
  end
elsif images.empty? && article_html.nil?
  puts "  No images (direct fetch was blocked; run with --browser-fetch to try Safari)"
end

hr
puts "Step 5: OCR images (#{images.size} total):"
images.each { |img| puts "    #{img}" }
puts "  (none)" if images.empty?

# ── 4. OCR each image ───────────────────────────────────────────────────────

hr
puts "OCR:"
all_ocr_domains = Set.new

if ocr_backend.nil?
  puts "  Skipped — no OCR backend"
elsif images.empty?
  puts "  Skipped — no images"
else
  images.each_with_index do |img_url, i|
    puts "  [#{i + 1}/#{images.size}] #{img_url}"
    text = ocr_image(img_url)
    if text.nil? || text.strip.empty?
      puts "    → no text recognised"
      next
    end

    ocr_domains = Set.new
    scan_text_for_domains(text, ocr_domains)

    if ocr_domains.any?
      ocr_domains.each { |d| puts "    → [DOMAIN] #{d}" }
      all_ocr_domains.merge(ocr_domains)
    else
      snippet = text.strip.gsub(/\s+/, ' ')[0, 120]
      puts "    → text (no [.] domains): \"#{snippet}\""
    end
  end
end

# ── 5. Summary ───────────────────────────────────────────────────────────────

hr('═')
puts "Summary"
hr('═')
puts "Text domains : #{text_domains.sort.join(', ').then { |s| s.empty? ? '(none)' : s }}"
puts "OCR domains  : #{all_ocr_domains.sort.join(', ').then { |s| s.empty? ? '(none)' : s }}"
all_found = (text_domains | all_ocr_domains).sort
puts "Combined     : #{all_found.empty? ? '(none)' : all_found.join(', ')}"
puts
