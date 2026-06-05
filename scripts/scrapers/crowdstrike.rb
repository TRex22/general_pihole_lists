# frozen_string_literal: true
# CrowdStrike Blog scraper
#
# crowdstrike.com blocks cloud/datacenter IPs (ECONNREFUSED).
# On residential/office network this works normally.
# Run with --browser-fetch if you get connection errors.
#
# Discovery order:
#   1. Sitemap at /sitemap.xml (filter /en-us/blog/)
#   2. HTML pagination at /en-us/blog/?page=N
#
# Article URLs: https://www.crowdstrike.com/en-us/blog/<slug>/

CROWDSTRIKE_BASE        = 'https://www.crowdstrike.com'
CROWDSTRIKE_SITEMAP_URL = "#{CROWDSTRIKE_BASE}/sitemap.xml"
CROWDSTRIKE_PATH_RE     = %r{crowdstrike\.com/en-us/blog/[a-z0-9][a-z0-9\-]+/?$}

class CrowdStrikeScraper < StandardPaginatedScraper
  SOURCE_NAME = 'CrowdStrike Blog'
  SOURCE_KEY  = 'crowdstrike'
  BASE_URL    = CROWDSTRIKE_BASE

  private

  def collect_article_urls
    articles = collect_via_sitemap(CROWDSTRIKE_SITEMAP_URL, path_re: CROWDSTRIKE_PATH_RE)
    return articles if articles&.any?

    warn '  Sitemap unavailable — trying HTML pagination (may require --browser-fetch).'
    super
  end

  def listing_url(page)
    page == 1 ? "#{CROWDSTRIKE_BASE}/en-us/blog/" \
              : "#{CROWDSTRIKE_BASE}/en-us/blog/?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('a[href*="/en-us/blog/"]').each do |link|
      href = link['href'].to_s.strip
      next if href.empty?
      href = href.start_with?('http') ? href : "#{CROWDSTRIKE_BASE}#{href}"
      next unless href.match?(CROWDSTRIKE_PATH_RE)
      next unless seen.add?(href)
      articles << { url: href, title: link.text.strip, date: nil, date_str: nil }
    end

    articles
  end

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
    doc.at_css('.blog-post__body, .entry-content, article, main') || doc.at_css('body')
  end

  def max_pages = 100
end
