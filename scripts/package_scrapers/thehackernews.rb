# frozen_string_literal: true
# The Hacker News package scraper — uses Blogger JSON feed API.
# Filters for supply-chain / malicious-package articles via title keyword matching.

PKG_THN_FEED_BASE = 'https://thehackernews.com/feeds/posts/default'
PKG_THN_MAX       = 25

# Article title keywords that indicate supply-chain / package content.
PKG_THN_TITLE_KEYWORDS = %w[
  package packages npm pypi rubygems crates.io nuget maven
  supply.chain typosquat dependency malicious.package
  open.source.poison backdoor stealer
].freeze

class PackageTHNScraper < PackageBaseScraper
  SOURCE_NAME = 'The Hacker News (packages)'
  SOURCE_KEY  = 'thehackernews'

  def run
    puts "Mode         : #{mode_label}"
    puts "Cache file   : #{@cache_file}"
    puts "Dry run      : #{@dry_run}"
    puts

    articles = collect_article_urls
    puts "\nTotal articles to process: #{articles.size}\n\n"
    pkg_scrape_articles_parallel(articles) if articles.any?

    save_cache
    pkg_print_summary
  end

  private

  def mode_label
    last = most_recent_cached_date
    if @years
      "full scan (#{@years} year(s))"
    elsif last
      overlap = @lookback_days&.positive? ? "#{@lookback_days}-day lookback" : "#{@pages_back} pages back"
      "incremental (#{overlap} from #{last})"
    else
      "first run — full scan (#{PKG_DEFAULT_YEARS} year(s))"
    end
  end

  def collect_article_urls
    cutoff            = Date.today << ((@years || PKG_DEFAULT_YEARS) * 12)
    last_date         = most_recent_cached_date
    incremental       = @years.nil? && !last_date.nil?
    articles          = []
    seen              = Set.new
    current_max       = Time.now.utc
    page              = 1
    pages_beyond_last = 0

    puts 'Collecting THN feed articles relevant to packages...'

    loop do
      encoded = URI.encode_www_form_component(current_max.strftime('%Y-%m-%dT%H:%M:%S+00:00'))
      url     = "#{PKG_THN_FEED_BASE}?updated-max=#{encoded}&max-results=#{PKG_THN_MAX}&alt=json"
      puts "  Page #{page}: before #{current_max.strftime('%Y-%m-%d %H:%M UTC')}"

      resp = fetch_with_retry(url)
      unless resp
        puts '  -> Failed, stopping.'
        break
      end

      data    = JSON.parse(resp.body)
      entries = data.dig('feed', 'entry') || []
      break if entries.empty?

      oldest_time = nil
      hit_cutoff  = false

      entries.each do |entry|
        href = entry['link']&.find { |l| l['rel'] == 'alternate' }&.dig('href')
        next if href.nil? || seen.include?(href)
        seen.add(href)

        published = (Time.parse(entry.dig('published', '$t')) rescue nil)
        next unless published

        if published.to_date < cutoff
          hit_cutoff = true
          break
        end

        oldest_time = published if oldest_time.nil? || published < oldest_time

        title = entry.dig('title', '$t').to_s
        # Only keep articles that mention package ecosystems
        next unless PKG_THN_TITLE_KEYWORDS.any? { |kw| title.downcase.match?(kw) }

        next if @cache['articles'][href]

        articles << {
          url:      href,
          date_str: published.to_date.to_s,
          title:    title.strip
        }
      end

      puts "  -> #{articles.size} total relevant"
      break if hit_cutoff

      break unless oldest_time

      if incremental
        if @lookback_days&.positive?
          break if oldest_time.to_date < (last_date - @lookback_days)
        elsif oldest_time.to_date < last_date
          pages_beyond_last += 1
          break if pages_beyond_last >= @pages_back
        end
      end

      current_max = oldest_time - 1
      page += 1
      sleep 0.5
    end

    articles
  end

  # THN blocks custom UAs via JA3 fingerprinting
  def request_headers = {}

  def article_content(doc)
    doc.at_css('.articlebody, .article-body, .post-body, #articlebody, article .entry-content, main') ||
      doc.at_css('body')
  end
end
