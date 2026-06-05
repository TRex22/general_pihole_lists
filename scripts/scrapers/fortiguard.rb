# frozen_string_literal: true
# FortiGuard Labs scraper
#
# fortinet.com blocks cloud/datacenter IPs at the TCP level (ECONNREFUSED).
# On a residential/office network this scraper works normally via HTML pagination.
# Run with --browser-fetch if you still get connection errors.
#
# Discovery order:
#   1. Sitemap at /sitemap.xml (filter /blog/threat-research/)
#   2. HTML pagination at /blog/threat-research (if sitemap unavailable)
#
# Article URLs: https://www.fortinet.com/blog/threat-research/<slug>

FORTIGUARD_BASE        = 'https://www.fortinet.com'
FORTIGUARD_SITEMAP_URL = "#{FORTIGUARD_BASE}/sitemap.xml"
FORTIGUARD_PATH_RE     = %r{fortinet\.com/blog/threat-research/[a-z0-9]}

class FortiguardScraper < StandardPaginatedScraper
  SOURCE_NAME = 'FortiGuard Labs'
  SOURCE_KEY  = 'fortiguard'
  BASE_URL    = FORTIGUARD_BASE

  private

  def collect_article_urls
    articles = collect_via_sitemap(FORTIGUARD_SITEMAP_URL, path_re: FORTIGUARD_PATH_RE)
    return articles if articles&.any?

    warn '  Sitemap unavailable — trying HTML pagination (may require --browser-fetch).'
    super
  end

  def listing_url(page)
    page == 1 ? "#{FORTIGUARD_BASE}/blog/threat-research" \
              : "#{FORTIGUARD_BASE}/blog/threat-research?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('a[href*="/blog/threat-research/"]').each do |link|
      href = link['href'].to_s.strip
      next if href.empty? || href.end_with?('/threat-research') || href.end_with?('/threat-research/')
      href = href.start_with?('http') ? href : "#{FORTIGUARD_BASE}#{href}"
      next unless href.match?(FORTIGUARD_PATH_RE)
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
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.blog-content, .entry-content, article, main') || doc.at_css('body')
  end

  def max_pages = 50
end
