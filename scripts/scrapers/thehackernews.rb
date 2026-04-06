# frozen_string_literal: true

# The Hacker News scraper
#
# Uses Blogger's JSON feed API for article listing, scrapes HTML for:
#   - Obfuscated domains (text, e.g. evil[.]com)
#   - Article screenshots/images → OCR → additional domains
#
# Loaded by scrape_malicious_domains.rb via require_relative.

THN_FEED_BASE_URL = 'https://thehackernews.com/feeds/posts/default'
THN_MAX_RESULTS   = 25  # Blogger API max per page

# Note: THN article images are hosted on blogger.googleusercontent.com/img/...
# and similar Blogger CDN URLs that carry NO file extension, so extension-based
# filtering is deliberately avoided. We rely on the article-content-area CSS
# selector and the skip-fragment list to exclude non-article images instead.

# URL substrings that indicate non-article images (ads, icons, tracking, social).
# Checked case-insensitively against the full resolved URL.
THN_IMAGE_SKIP_FRAGMENTS = %w[
  doubleclick.net googlesyndication.com adserv advert
  /pixel. /1x1. /tracking /beacon /analytics /stat.
  /social/ /share-button /twitter-bird /fb-button /whatsapp
  /favicon /apple-touch-icon /touch-icon
  gravatar.com /avatar/ /author- /author_
  /logo. /badge. /icon-
  feeds.feedburner.com
].freeze

class THNScraper < BaseScraper
  SOURCE_NAME = 'The Hacker News'
  SOURCE_KEY  = 'thehackernews'

  def initialize(years:, pages_back:, parallel:, output_file:, cache:, full_cache:,
                 cache_file:, dry_run:, rescan_images: false, lookback_days: nil,
                 browser_fetch: false)
    super(output_file: output_file, cache: cache, full_cache: full_cache,
          cache_file: cache_file, dry_run: dry_run, browser_fetch: browser_fetch)
    @years         = years
    @pages_back    = pages_back
    @lookback_days = lookback_days
    @parallel      = parallel
    @rescan_images = rescan_images
  end

  def run
    last_scraped = most_recent_cached_date
    incremental  = @years.nil? && !last_scraped.nil?

    if incremental
      overlap_label = @lookback_days&.positive? ? "#{@lookback_days}-day lookback" : "#{@pages_back} pages back"
      puts "Mode             : incremental (#{overlap_label} from #{last_scraped})"
    elsif @years
      puts "Mode             : full scan (#{@years} year(s))"
    else
      puts "Mode             : first run — full scan (#{DEFAULT_YEARS} year(s))"
    end
    puts "Parallel workers : #{@parallel}"
    puts "Output file      : #{@output_file}"
    puts "Cache file       : #{@cache_file}"
    puts "Dry run          : #{@dry_run}"
    overlap_desc = @lookback_days&.positive? ? "#{@lookback_days} day(s) lookback" : "#{@pages_back} pages back"
    puts "Overlap window   : #{overlap_desc}"
    puts "OCR backend      : #{ocr_backend || 'none'}"
    puts "Rescan images    : #{@rescan_images}"
    puts "Browser fetch    : #{@browser_fetch ? "enabled (Safari/osascript, macOS only)" : 'disabled (use --browser-fetch to enable)'}"
    puts

    warn_if_no_ocr_backend

    # Compile the macOS OCR helper once up front, before threads start.
    ensure_macos_ocr_compiled if ocr_backend == :macos

    articles = collect_article_urls
    puts "\nTotal articles to process: #{articles.size}\n\n"
    scrape_articles_parallel(articles) if articles.any?

    # Optional pass: OCR images in cached articles not yet processed.
    rescan_images_in_cache if @rescan_images

    unless @dry_run
      clean_blocklist
      write_to_blocklist
    end

    save_cache
    print_summary
  end

  private

  # ── Article collection via Blogger JSON feed API ────────────────────────────

  def collect_article_urls
    last_scraped      = most_recent_cached_date
    incremental       = @years.nil? && !last_scraped.nil?
    cutoff            = Date.today << ((@years || DEFAULT_YEARS) * 12)
    pages_beyond_last = 0

    puts 'Collecting article URLs from Blogger feed...'

    current_max = Time.now.utc
    articles    = []
    seen        = Set.new
    page        = 1

    loop do
      encoded = URI.encode_www_form_component(current_max.strftime('%Y-%m-%dT%H:%M:%S+00:00'))
      url     = "#{THN_FEED_BASE_URL}?updated-max=#{encoded}&max-results=#{THN_MAX_RESULTS}&alt=json"

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

        # Capture the feed entry's HTML fragment. Note: the Blogger JSON feed
        # only returns a truncated summary (~400 bytes), not the full article.
        # THN's direct article URLs are Cloudflare-protected, so we rely on
        # --browser-fetch (Safari/osascript) to get inline article images.
        content_html = entry.dig('content', '$t') || entry.dig('summary', '$t')

        articles << {
          url:             href,
          date_str:        published.to_date.to_s,
          title:           entry.dig('title', '$t')&.strip,
          feed_updated_at: feed_updated_at,
          force_rescrape:  force_rescrape,
          content_html:    content_html
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

      # Incremental overlap window — two modes:
      #   lookback_days: stop once oldest article on the page is more than N days
      #                  before the last cached date (day-granularity, predictable).
      #   pages_back:    stop after N pages whose oldest article predates the last
      #                  cached date (default, page-granularity).
      if incremental
        if @lookback_days&.positive?
          day_floor = last_scraped - @lookback_days
          if oldest_time.to_date < day_floor
            puts "  -> Reached #{@lookback_days}-day lookback before #{last_scraped} (floor: #{day_floor}), stopping."
            break
          end
        elsif oldest_time.to_date < last_scraped
          pages_beyond_last += 1
          if pages_beyond_last >= @pages_back
            puts "  -> #{@pages_back} overlap page(s) fetched past #{last_scraped}, stopping."
            break
          end
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

  # ── Parallel article scraping ───────────────────────────────────────────────

  def scrape_articles_parallel(articles)
    batches = articles.each_slice(@parallel).to_a
    batches.tqdm(desc: 'Scraping articles', total: batches.size, unit: 'batch').each do |batch|
      threads = batch.map { |article| Thread.new { scrape_article(article) } }
      threads.each(&:join)
      # Checkpoint: persist cache after every batch so a crash loses at most
      # one batch of work rather than the entire run.
      save_cache(quiet: true)
    end
  end

  def scrape_article(article)
    url = article[:url]

    # collect_article_urls only enqueues articles that are new or force_rescrape,
    # so a cached entry here means it was updated since last scrape.
    if article[:force_rescrape]
      @mutex.synchronize { puts "  [UPDATED ] #{url} — re-scraping" }
    end

    # THN's article URLs sit behind a Cloudflare JS challenge so direct HTTP
    # returns a challenge page. The Blogger JSON feed provides only a truncated
    # summary (~400 bytes) — enough for text domain extraction but no images.
    html = article[:content_html]

    if html.nil? || html.strip.empty?
      response = fetch_with_retry(url)
      unless response
        @mutex.synchronize { puts "  [FAILED] #{url}" }
        return
      end
      html = response.body
    end

    if cloudflare_challenge?(html)
      @mutex.synchronize { puts "  [CF-BLOCK] #{url} — Cloudflare challenge, skipping" }
      return
    end

    doc    = Nokogiri::HTML(html)
    title  = article[:title] || doc.at_css('h1.post-title, h1')&.text&.strip

    # ── Text-based domain extraction ────────────────────────────────────────
    text_domains = extract_text_domains(doc)

    # ── Image extraction ────────────────────────────────────────────────────
    images = extract_images(doc, url)

    # Feed summary rarely contains inline article images. When browser fetch is
    # enabled, open the URL in Safari (which handles the Cloudflare JS challenge)
    # to get the fully-rendered article HTML and extract images from it.
    if images.empty? && @browser_fetch && browser_fetch_available?
      @mutex.synchronize { puts "  [BROWSER ] #{url} — opening in Safari for image extraction" }
      browser_html = fetch_via_browser(url)
      if browser_html && !cloudflare_challenge?(browser_html)
        browser_doc  = Nokogiri::HTML(browser_html)
        images       = extract_images(browser_doc, url)
        # Merge any additional text domains from the full article body
        browser_text = extract_text_domains(browser_doc)
        text_domains = (Set.new(text_domains) | browser_text).to_a.sort
      end
    end

    # ── OCR ─────────────────────────────────────────────────────────────────
    ocr_doms    = extract_domains_from_images(images)
    all_domains = (Set.new(text_domains) | ocr_doms).to_a.sort

    entry = {
      'url'                  => url,
      'title'                => title,
      'date'                 => article[:date_str],
      'feed_updated_at'      => article[:feed_updated_at],
      'scraped_at'           => Time.now.utc.iso8601,
      'domains'              => all_domains,
      'images'               => images,
      'image_ocr_domains'    => ocr_doms.to_a.sort,
      'images_ocr_at'        => (images.any? && ocr_backend ? Time.now.utc.iso8601 : nil),
      'written_to_blocklist' => false
    }

    @mutex.synchronize do
      @cache['articles'][url] = entry

      label = all_domains.any? ? "[FOUND #{all_domains.size.to_s.rjust(3)}]" : '[NO DOMAINS ]'
      puts "  #{label} #{url}"
      all_domains.each { |d| puts "               #{d}" }
      puts "               (#{images.size} image(s) found, #{ocr_doms.size} via OCR)" if images.any?

      @pending[url] = { domains: all_domains, title: title, date: article[:date_str] } if all_domains.any?
    end
  end

  # ── Image rescan pass ───────────────────────────────────────────────────────

  # Re-processes cached articles that have images not yet OCR'd, or articles
  # where images haven't been extracted at all. Adds any newly-found domains
  # to @pending so they are written to the blocklist.
  def rescan_images_in_cache
    puts "\nImage rescan: checking cached articles for unprocessed screenshots..."

    to_scan = @cache['articles'].select do |_, entry|
      # Articles with no image field → need HTML re-fetch + OCR
      # Articles with images but no OCR timestamp → need OCR
      entry['images'].nil? ||
        (entry['images'].is_a?(Array) && entry['images'].any? && entry['images_ocr_at'].nil?)
    end

    if to_scan.empty?
      puts '  All cached articles already have image data — nothing to rescan.'
      return
    end

    puts "  Articles to rescan: #{to_scan.size}"

    to_scan.each do |url, entry|
      puts "  [RESCAN] #{url}"

      # Fetch HTML if we don't have image URLs yet.
      # Direct URLs are Cloudflare-protected; use browser fetch if enabled.
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

      # Run OCR
      ocr_domains = extract_domains_from_images(images)
      entry['images_ocr_at']     = Time.now.utc.iso8601
      entry['image_ocr_domains'] = ocr_domains.to_a.sort

      if ocr_domains.empty?
        save_cache(quiet: true)
        next
      end

      # Merge newly-found OCR domains into the article's domains
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

      # Checkpoint after each article regardless of whether new domains were found.
      save_cache(quiet: true)
    end
  end

  # ── Domain extraction ───────────────────────────────────────────────────────

  def extract_text_domains(doc)
    domains = Set.new
    content = article_content(doc)
    return [] unless content
    scan_text_for_domains(content.text, domains)
    domains.to_a.sort
  end

  # Detects a Cloudflare managed-challenge page returned instead of article HTML.
  def cloudflare_challenge?(html)
    html.include?('Enable JavaScript and cookies to continue') ||
      html.include?('_cf_chl_opt') ||
      html.include?('cf-browser-verification')
  end

  def article_content(doc)
    # Try article-specific selectors first (full-page scrape).
    # When parsing Blogger feed content (an HTML fragment), none of these will
    # match and we fall back to <body>, which Nokogiri wraps the fragment in —
    # so it correctly contains exactly the article content and nothing else.
    doc.at_css('.articlebody, .article-body, .post-body, #articlebody, article .entry-content, main') ||
      doc.at_css('body')
  end

  # ── Image extraction ────────────────────────────────────────────────────────

  # Returns an array of absolute image URLs found within the article content
  # area, filtered to remove ads, tracking pixels, icons, and social buttons.
  #
  # No file-extension check: Blogger CDN URLs (blogger.googleusercontent.com/img/...)
  # have no extension. We rely on the content-area CSS scope and skip-fragment
  # list instead.
  def extract_images(doc, base_url)
    content = article_content(doc)
    return [] unless content

    base_uri = URI.parse(base_url)
    seen     = Set.new
    images   = []

    content.css('img').each do |img|
      # Try every common src attribute, including lazy-load variants and srcset.
      # srcset may contain multiple space/comma-separated entries; take the first URL.
      src = img['src']           ||
            img['data-src']      ||
            img['data-lazy-src'] ||
            img['data-original'] ||
            img['data-lazy']     ||
            img['srcset']&.split(/[\s,]+/)&.first

      next if src.nil? || src.strip.empty?
      next if src.start_with?('data:')   # inline data URIs

      url = resolve_url(src, base_uri)
      next unless url&.start_with?('http')   # must be an absolute HTTP(S) URL
      next if THN_IMAGE_SKIP_FRAGMENTS.any? { |f| url.downcase.include?(f) }

      # Skip images explicitly declared as tiny — likely icons or tracking pixels.
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
end
