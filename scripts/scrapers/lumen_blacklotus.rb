# frozen_string_literal: true
# Lumen Black Lotus Labs scraper
#
# blog.lumen.com redirects to lumen.com/blog-and-news/en-us/home (AEM CMS).
# No URL pagination — uses sitemap for article discovery.
# Filter: paths containing "black-lotus" or "security" in the blog path.
#
# Article URLs: https://www.lumen.com/blog-and-news/en-us/<slug>

LUMEN_BASE        = 'https://www.lumen.com'
LUMEN_SITEMAP_URL = "#{LUMEN_BASE}/sitemap.xml"
LUMEN_PATH_RE     = %r{lumen\.com/(?:blog(?:-and-news)?|en-us)/.*(?:black[-\s]?lotus|securit|threat)}i

class LumenBlackLotusLabsScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Lumen Black Lotus Labs'
  SOURCE_KEY  = 'lumen_blacklotus'
  BASE_URL    = LUMEN_BASE

  private

  def collect_article_urls
    articles = collect_via_sitemap(LUMEN_SITEMAP_URL, path_re: LUMEN_PATH_RE)
    return articles if articles&.any?

    warn '  Sitemap empty or unreachable — trying blog listing page.'
    collect_via_listing_crawl
  end

  def collect_via_listing_crawl
    resp = fetch_with_retry("#{LUMEN_BASE}/blog-and-news/en-us/home")
    return [] unless resp&.success?

    doc      = Nokogiri::HTML(resp.body)
    articles = []
    seen     = Set.new

    doc.css('a[href*="black-lotus"], a[href*="security"], a[href*="threat"]').each do |link|
      href = link['href'].to_s.strip
      next if href.empty?
      href = href.start_with?('http') ? href : "#{LUMEN_BASE}#{href}"
      next unless href.match?(LUMEN_PATH_RE)
      next unless seen.add?(href)
      next if @cache['articles'][href]
      articles << { url: href, title: link.text.strip, date: nil, date_str: nil }
    end

    puts "  -> #{articles.size} articles from listing page"
    articles
  end

  def listing_url(page) = "#{LUMEN_BASE}/blog-and-news/en-us/home"
  def parse_listing(_doc) = []

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
    doc.at_css('.article-content, .blog-content, article, main') || doc.at_css('body')
  end
end
