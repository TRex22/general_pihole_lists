# frozen_string_literal: true
# Huntress Labs scraper
#
# huntress.com uses Builder.io (headless CMS) with JS-only pagination.
# Sitemap shows /blog hub but not individual posts — HTML listing fallback needed.
# Run with --browser-fetch for JavaScript-rendered content.
#
# Discovery order:
#   1. Sitemap at /sitemap.xml (filter /blog/ paths)
#   2. HTML /all-blog-posts listing (confirmed: shows 42 pages of posts as of 2026)
#
# Article URLs: https://www.huntress.com/blog/<slug>

HUNTRESS_BASE        = 'https://www.huntress.com'
HUNTRESS_SITEMAP_URL = "#{HUNTRESS_BASE}/sitemap.xml"
HUNTRESS_PATH_RE     = %r{huntress\.com/blog/[a-z0-9][a-z0-9\-]+/?$}

class HuntressScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Huntress Labs'
  SOURCE_KEY  = 'huntress'
  BASE_URL    = HUNTRESS_BASE

  private

  def collect_article_urls
    articles = collect_via_sitemap(HUNTRESS_SITEMAP_URL, path_re: HUNTRESS_PATH_RE)
    return articles if articles&.any?

    warn '  Sitemap has no individual blog posts — trying /all-blog-posts (may require --browser-fetch).'
    super
  end

  def listing_url(page)
    page == 1 ? "#{HUNTRESS_BASE}/all-blog-posts" \
              : "#{HUNTRESS_BASE}/all-blog-posts?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('a[href*="/blog/"]').each do |link|
      href = link['href'].to_s.strip
      next if href.empty?
      href = href.start_with?('http') ? href : "#{HUNTRESS_BASE}#{href}"
      next unless href.match?(HUNTRESS_PATH_RE)
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
