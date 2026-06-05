# frozen_string_literal: true
# Red Canary scraper
#
# No URL-based pagination found on listing page (uses JS filter widgets).
# Sitemap (sitemap_index → post-sitemap.xml + threat-sitemap.xml) is the discovery path.
#
# Blog articles use a two-level path: /blog/<category>/<slug>/
# e.g. /blog/threat-detection/detection-profile-silent-periodic-activity/
#
# Threat profiles are also useful: /threat-detection-report/threats/<slug>/

RED_CANARY_BASE        = 'https://redcanary.com'
RED_CANARY_SITEMAP_URL = "#{RED_CANARY_BASE}/sitemap.xml"

# Matches /blog/[category]/[slug]/ (two-level) and /threat-detection-report/threats/[slug]/
RED_CANARY_PATH_RE = %r{
  redcanary\.com/blog/[a-z0-9][a-z0-9\-]+/[a-z0-9][a-z0-9\-]+/?$ |
  redcanary\.com/threat-detection-report/threats/[a-z0-9][a-z0-9\-]+/?$
}x

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
      data = JSON.parse(scrub(ld.text)) rescue {}
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
