# frozen_string_literal: true
# Zscaler ThreatLabz scraper
#
# Zscaler's blog pagination is JavaScript-only (Next.js carousel).
# The sitemap at /sitemap.xml is the only reliable way to enumerate articles.
# Filters to /blogs/security-research/ paths only.
#
# Article URLs: https://www.zscaler.com/blogs/security-research/<slug>

ZSCALER_BASE        = 'https://www.zscaler.com'
ZSCALER_SITEMAP_URL = "#{ZSCALER_BASE}/sitemap.xml"
ZSCALER_PATH_RE     = %r{zscaler\.com/blogs/security-research/[a-z0-9]}

class ZscalerThreatLabzScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Zscaler ThreatLabz'
  SOURCE_KEY  = 'zscaler_threatlabz'
  BASE_URL    = ZSCALER_BASE

  private

  def collect_article_urls
    collect_via_sitemap(ZSCALER_SITEMAP_URL, path_re: ZSCALER_PATH_RE) || []
  end

  def listing_url(page) = "#{ZSCALER_BASE}/blogs/security-research"
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
      pub = data['datePublished']
      return Date.parse(pub) if pub
    end
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.blog-content, .post-body, article, main') || doc.at_css('body')
  end

  # Zscaler rate-limits aggressively — cap workers and add inter-batch delay
  # to avoid triggering 429s. The global MIN_REQUEST_INTERVAL still applies.
  def parallel_workers = [@parallel, 5].min
  def batch_delay      = 3
end
