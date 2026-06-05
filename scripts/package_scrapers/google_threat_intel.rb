# frozen_string_literal: true
# Google Cloud / Mandiant Threat Intelligence Blog package scraper
#
# The listing page uses a JS "Load more stories" button — server-side pagination
# via query params does not work. RSS feed is the authoritative programmatic source.
#
# RSS feed: https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v
# Confirmed returning recent articles with correct URLs and pubDates.

PKG_GOOGLE_RSS   = 'https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v'
PKG_GOOGLE_BASE  = 'https://cloud.google.com'
PKG_GOOGLE_TOPIC = "#{PKG_GOOGLE_BASE}/blog/topics/threat-intelligence"

class PackageGoogleThreatIntelScraper < PackageBaseScraper
  SOURCE_NAME = 'Google Cloud Threat Intelligence (packages)'
  SOURCE_KEY  = 'google_threat_intel'

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

    puts "Mode        : #{mode} [RSS feed]"
    puts "Cache file  : #{@cache_file}"
    puts "Dry run     : #{@dry_run}"
    puts

    articles = collect_article_urls
    puts "\nTotal articles to process: #{articles.size}\n\n"
    pkg_scrape_articles_parallel(articles) if articles.any?

    save_cache
    pkg_print_summary
  end

  private

  def collect_article_urls
    cutoff      = Date.today << ((@years || PKG_DEFAULT_YEARS) * 12)
    last_date   = most_recent_cached_date
    incremental = @years.nil? && !last_date.nil?

    puts "  Fetching Google TI RSS feed..."
    resp = fetch_with_retry(PKG_GOOGLE_RSS)
    unless resp
      warn '  -> RSS feed unreachable.'
      return []
    end

    xml = Nokogiri::XML(resp.body)
    articles = []

    xml.css('item').each do |item|
      link     = item.at_css('link')&.text&.strip ||
                 item.at_css('guid')&.text&.strip
      title    = item.at_css('title')&.text&.strip
      pub_date = item.at_css('pubDate')&.text&.strip

      next unless link&.include?('cloud.google.com')

      date = pub_date ? (Date.parse(pub_date) rescue nil) : nil
      next if date && date < cutoff

      if incremental && date && last_date
        lookback = @lookback_days&.positive? ? last_date - @lookback_days : last_date
        next if date < lookback
      end

      next if @cache['articles'][link]

      articles << { url: link, title: title, date_str: date&.to_s, date: date }
    end

    puts "  -> #{articles.size} uncached articles in feed"
    articles
  end

  def extract_article_date(doc)
    meta = doc.at_css('meta[property="article:published_time"]')
    return Date.parse(meta['content']) if meta
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.blog-article__content, article, main') || doc.at_css('body')
  end
end
