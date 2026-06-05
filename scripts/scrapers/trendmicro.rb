# frozen_string_literal: true
# Trend Micro Research scraper
#
# trendmicro.com returns 403 to non-browser HTTP clients on some network ranges.
# Run with --browser-fetch if you get empty results.
#
# Discovery order:
#   1. Sitemap at /sitemap.xml (filter /en_us/research/)
#   2. HTML pagination at /en_us/research.html?page=N
#
# Article URLs: https://www.trendmicro.com/en_us/research/<YYYY>/<slug>.html

TRENDMICRO_BASE        = 'https://www.trendmicro.com'
TRENDMICRO_SITEMAP_URL = "#{TRENDMICRO_BASE}/sitemap.xml"
TRENDMICRO_PATH_RE     = %r{trendmicro\.com/en_us/research/\d{2,4}/[a-z0-9]}

class TrendMicroScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Trend Micro Research'
  SOURCE_KEY  = 'trendmicro'
  BASE_URL    = TRENDMICRO_BASE

  private

  def collect_article_urls
    articles = collect_via_sitemap(TRENDMICRO_SITEMAP_URL, path_re: TRENDMICRO_PATH_RE)
    return articles if articles&.any?

    warn '  Sitemap unavailable — trying HTML pagination (may require --browser-fetch).'
    super
  end

  def listing_url(page)
    page == 1 ? "#{TRENDMICRO_BASE}/en_us/research.html" \
              : "#{TRENDMICRO_BASE}/en_us/research.html?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('a[href*="/en_us/research/"]').each do |link|
      href = link['href'].to_s.strip
      next if href.empty?
      href = href.start_with?('http') ? href : "#{TRENDMICRO_BASE}#{href}"
      next unless href.match?(TRENDMICRO_PATH_RE)
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
    doc.at_css('.entry-content, .article-body, article, main') || doc.at_css('body')
  end

  def max_pages = 100
end
