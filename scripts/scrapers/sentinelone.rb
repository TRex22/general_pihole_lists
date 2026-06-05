# frozen_string_literal: true
# SentinelOne Labs scraper
#
# Incremental mode: RSS feed at /blog/feed/ (fast, ~10 most recent items)
# Full scan (--years N): HTML pagination at /blog/page/N/ (142+ pages as of 2026)
#
# SentinelOne uses a custom headless CMS; no WordPress REST API.
# Article URLs: https://www.sentinelone.com/blog/<slug>/

SENTINELONE_BASE    = 'https://www.sentinelone.com'
SENTINELONE_RSS_URL = "#{SENTINELONE_BASE}/blog/feed/"

class SentinelOneScraper < StandardPaginatedScraper
  SOURCE_NAME = 'SentinelOne Labs'
  SOURCE_KEY  = 'sentinelone'
  BASE_URL    = SENTINELONE_BASE

  private

  def collect_article_urls
    incremental = @years.nil? && !most_recent_cached_date.nil?
    return (collect_via_rss(SENTINELONE_RSS_URL) || super) if incremental

    super
  end

  def listing_url(page)
    page == 1 ? "#{SENTINELONE_BASE}/blog/" : "#{SENTINELONE_BASE}/blog/page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('article, .post, [class*="BlogPost"], [class*="blog-post"]').each do |node|
      link = node.at_css('a[href*="/blog/"]')
      next unless link

      href = link['href'].to_s.strip
      next if href.empty?
      href = href.start_with?('http') ? href : "#{SENTINELONE_BASE}#{href}"
      next unless href.match?(%r{sentinelone\.com/blog/[a-z0-9]})
      next if href.chomp('/') == "#{SENTINELONE_BASE}/blog"
      next unless seen.add?(href)

      title = (node.at_css('h1, h2, h3')&.text || link.text).strip
      date  = extract_node_date(node)
      articles << { url: href, title: title, date: date, date_str: date&.to_s }
    end

    if articles.empty?
      doc.css('a[href*="/blog/"]').each do |link|
        href = link['href'].to_s.strip
        href = href.start_with?('http') ? href : "#{SENTINELONE_BASE}#{href}"
        next unless href.match?(%r{sentinelone\.com/blog/[a-z0-9\-]{4,}/?$})
        next unless seen.add?(href)
        articles << { url: href, title: link.text.strip, date: nil, date_str: nil }
      end
    end

    articles.uniq { |a| a[:url] }
  end

  def extract_node_date(node)
    time_el = node.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    span = node.at_css('[class*="date"], [class*="Date"], .published')
    return Date.parse(span.text.strip) if span
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def extract_article_date(doc)
    meta = doc.at_css('meta[property="article:published_time"]') ||
           doc.at_css('meta[name="date"]')
    return Date.parse(meta['content']) if meta
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.article-body, .post-content, .entry-content, article, main') ||
      doc.at_css('body')
  end

  def max_pages          = 150
  def listing_page_delay = 0.5
end
