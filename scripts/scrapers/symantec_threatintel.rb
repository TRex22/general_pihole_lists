# frozen_string_literal: true
# Symantec Threat Intelligence scraper
#
# symantec-enterprise-blogs.security.com now redirects to security.com.
# JS-rendered (Next.js) with Load-More pagination — no URL-based pagination.
# Uses sitemap for article discovery, falling back to crawling the listing page.
#
# Article URLs: https://www.security.com/threat-intelligence/<slug>

SYMANTEC_BASE        = 'https://www.security.com'
SYMANTEC_SITEMAP_URL = "#{SYMANTEC_BASE}/sitemap.xml"
SYMANTEC_PATH_RE     = %r{security\.com/threat-intelligence/[a-z0-9]}

class SymantecThreatIntelScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Symantec Threat Intelligence'
  SOURCE_KEY  = 'symantec_threatintel'
  BASE_URL    = SYMANTEC_BASE

  private

  def collect_article_urls
    articles = collect_via_sitemap(SYMANTEC_SITEMAP_URL, path_re: SYMANTEC_PATH_RE)
    return articles if articles&.any?

    warn '  Sitemap empty or unreachable — falling back to listing page crawl.'
    collect_via_listing_crawl
  end

  def collect_via_listing_crawl
    resp = fetch_with_retry("#{SYMANTEC_BASE}/threat-intelligence")
    return [] unless resp&.success?

    doc      = Nokogiri::HTML(resp.body)
    articles = []
    seen     = Set.new

    doc.css('a[href*="/threat-intelligence/"]').each do |link|
      href = link['href'].to_s.strip
      next if href.empty?
      href = href.start_with?('http') ? href : "#{SYMANTEC_BASE}#{href}"
      next unless href.match?(SYMANTEC_PATH_RE)
      next unless seen.add?(href)
      next if @cache['articles'][href]

      articles << { url: href, title: link.text.strip, date: nil, date_str: nil }
    end

    puts "  -> #{articles.size} articles from listing page"
    articles
  end

  def listing_url(page) = "#{SYMANTEC_BASE}/threat-intelligence"
  def parse_listing(_doc) = []

  def extract_article_date(doc)
    meta = doc.at_css('meta[property="article:published_time"]')
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
    doc.at_css('.article-body, .content-body, article, main') || doc.at_css('body')
  end
end
