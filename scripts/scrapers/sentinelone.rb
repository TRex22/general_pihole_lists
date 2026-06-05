# frozen_string_literal: true
# SentinelOne Labs scraper
#
# Incremental mode: RSS feed at /blog/feed/ (fast, ~10 most recent items)
# Full scan (--years N): Yoast SEO sitemap (sitemap.xml index → post-sitemap.xml +
#   post-sitemap2.xml + labs-sitemap.xml). Sitemaps have lastmod dates so cutoff
#   filtering works correctly — no more scanning all 150 HTML pages.
#
# Article URLs:
#   https://www.sentinelone.com/blog/<slug>/   (blog posts)
#   https://www.sentinelone.com/labs/<slug>/   (security labs research)

SENTINELONE_BASE        = 'https://www.sentinelone.com'
SENTINELONE_RSS_URL     = "#{SENTINELONE_BASE}/blog/feed/"
SENTINELONE_SITEMAP_URL = "#{SENTINELONE_BASE}/sitemap.xml"

# Matches /blog/<slug>/ and /labs/<slug>/ — excludes hub, category, author pages
SENTINELONE_PATH_RE = %r{
  sentinelone\.com/blog/[a-z0-9][a-z0-9\-]+/?$ |
  sentinelone\.com/labs/[a-z0-9][a-z0-9\-]+/?$
}x

class SentinelOneScraper < StandardPaginatedScraper
  SOURCE_NAME = 'SentinelOne Labs'
  SOURCE_KEY  = 'sentinelone'
  BASE_URL    = SENTINELONE_BASE

  private

  def collect_article_urls
    incremental = @years.nil? && !most_recent_cached_date.nil?
    return (collect_via_rss(SENTINELONE_RSS_URL) || collect_from_sitemap) if incremental

    collect_from_sitemap
  end

  def collect_from_sitemap
    collect_via_sitemap(SENTINELONE_SITEMAP_URL, path_re: SENTINELONE_PATH_RE) || []
  end

  # Stubs — only used if sitemap is unavailable and collect_article_urls calls super
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
      next unless href.match?(SENTINELONE_PATH_RE)
      next if href.chomp('/') == "#{SENTINELONE_BASE}/blog"
      next unless seen.add?(href)

      title = (node.at_css('h1, h2, h3')&.text || link.text).strip
      articles << { url: href, title: title, date: nil, date_str: nil }
    end

    articles.uniq { |a| a[:url] }
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

  def max_pages = 150
end
