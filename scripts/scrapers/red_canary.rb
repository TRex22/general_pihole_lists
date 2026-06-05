# frozen_string_literal: true
# Red Canary scraper
#
# No URL-based pagination found on listing page (uses JS filter widgets).
# Sitemap is the reliable discovery path.
# Articles are under /blog/<slug>/ — other /resources/ paths skipped.
#
# Article URLs: https://redcanary.com/blog/<slug>/

RED_CANARY_BASE        = 'https://redcanary.com'
RED_CANARY_SITEMAP_URL = "#{RED_CANARY_BASE}/sitemap.xml"
RED_CANARY_PATH_RE     = %r{redcanary\.com/blog/[a-z0-9][a-z0-9\-]+/?$}

class RedCanaryScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Red Canary'
  SOURCE_KEY  = 'red_canary'
  BASE_URL    = RED_CANARY_BASE

  private

  def collect_article_urls
    collect_via_sitemap(RED_CANARY_SITEMAP_URL, path_re: RED_CANARY_PATH_RE) || []
  end

  def listing_url(page) = "#{RED_CANARY_BASE}/blog/"
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
    doc.at_css('.blog-post__content, .entry-content, article, main') || doc.at_css('body')
  end
end
