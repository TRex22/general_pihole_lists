# frozen_string_literal: true
# Elastic Security Labs scraper
#
# Incremental mode: RSS feed at /security-labs/rss/feed.xml (confirmed working)
# Full scan (--years N): sitemap at /security-labs/sitemap.xml
#
# Elastic uses a Next.js static site; no WordPress REST API.
# Article URLs: https://www.elastic.co/security-labs/<slug>

ELASTIC_BASE        = 'https://www.elastic.co'
ELASTIC_RSS_URL     = "#{ELASTIC_BASE}/security-labs/rss/feed.xml"
ELASTIC_SITEMAP_URL = "#{ELASTIC_BASE}/security-labs/sitemap.xml"
ELASTIC_PATH_RE     = %r{elastic\.co/security-labs/[a-z0-9][a-z0-9\-]+/?$}

class ElasticSecurityScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Elastic Security Labs'
  SOURCE_KEY  = 'elastic_security'
  BASE_URL    = ELASTIC_BASE

  private

  def collect_article_urls
    incremental = @years.nil? && !most_recent_cached_date.nil?

    if incremental
      rss = collect_via_rss(ELASTIC_RSS_URL)
      return rss if rss
    end

    collect_via_sitemap(ELASTIC_SITEMAP_URL, path_re: ELASTIC_PATH_RE) || []
  end

  def listing_url(page) = "#{ELASTIC_BASE}/security-labs"
  def parse_listing(_doc) = []

  def extract_article_date(doc)
    meta = doc.at_css('meta[property="article:published_time"]') ||
           doc.at_css('meta[name="date"]')
    return Date.parse(meta['content']) if meta
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    ld = doc.at_css('script[type="application/ld+json"]')
    if ld
      data = JSON.parse(ld.text) rescue {}
      pub = data['datePublished'] || data['dateCreated']
      return Date.parse(pub) if pub
    end
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.prose, .article-body, article, main') || doc.at_css('body')
  end
end
