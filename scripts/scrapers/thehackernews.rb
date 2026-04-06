# frozen_string_literal: true

# The Hacker News scraper
#
# Uses Blogger's JSON feed API for article listing (reliable, structured).
# Scrapes individual article HTML pages for domain extraction.
#
# Loaded by scrape_malicious_domains.rb via require_relative.

THN_FEED_BASE_URL = 'https://thehackernews.com/feeds/posts/default'
THN_MAX_RESULTS   = 25  # Blogger API max per page

class THNScraper < BaseScraper
  SOURCE_NAME = 'The Hacker News'
  SOURCE_KEY  = 'thehackernews'

  def initialize(years:, pages_back:, parallel:, output_file:, cache:, full_cache:, cache_file:, dry_run:)
    super(output_file: output_file, cache: cache, full_cache: full_cache, cache_file: cache_file, dry_run: dry_run)
    @years      = years
    @pages_back = pages_back
    @parallel   = parallel
  end

  def run
    last_scraped = most_recent_cached_date
    incremental  = @years.nil? && !last_scraped.nil?

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

  # ── Parallel article scraping ───────────────────────────────────────────────

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

  # ── Domain extraction ───────────────────────────────────────────────────────

  def extract_domains(doc)
    domains = Set.new

    content = doc.at_css('.articlebody, .article-body, .post-body, #articlebody, article .entry-content, main') ||
              doc.at_css('body')
    return [] unless content

    scan_text_for_domains(content.text, domains)
    domains.to_a.sort
  end
end
