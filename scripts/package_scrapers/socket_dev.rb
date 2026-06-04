# frozen_string_literal: true
# Socket.dev Security Research blog scraper
# Pagination: ?page=N (13+ pages of articles)
# Every article is about a specific malicious package discovered by Socket.

SOCKET_DEV_BASE = 'https://socket.dev'

class SocketDevScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Socket.dev Security Research'
  SOURCE_KEY  = 'socket_dev'
  BASE_URL    = SOCKET_DEV_BASE

  private

  def listing_url(page)
    page == 1 ? "#{SOCKET_DEV_BASE}/blog" : "#{SOCKET_DEV_BASE}/blog?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    # Socket uses various article card class names
    selectors = 'article, [class*="ArticleCard"], [class*="article-card"], [class*="BlogPost"], [class*="blog-post"]'
    doc.css(selectors).each do |art|
      link = art.at_css('a[href*="/blog/"]')
      next unless link

      href = link['href'].to_s
      next if href.empty? || href == "#{SOCKET_DEV_BASE}/blog"
      href = href.start_with?('http') ? href : "#{SOCKET_DEV_BASE}#{href}"
      next unless href.match?(%r{socket\.dev/blog/[^?#]+$})
      next unless seen.add?(href)

      title = (art.at_css('h1, h2, h3')&.text || link.text).strip
      date  = parse_article_date(art)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end

    # Fallback: any /blog/ article link on the page
    if articles.empty?
      doc.css('a[href*="/blog/"]').each do |link|
        href = link['href'].to_s
        href = href.start_with?('http') ? href : "#{SOCKET_DEV_BASE}#{href}"
        next unless href.match?(%r{socket\.dev/blog/[a-z0-9\-]+/?$})
        next unless seen.add?(href)
        articles << { url: href, title: link.text.strip, date_str: nil, date: nil }
      end
    end

    articles
  end

  def parse_article_date(node)
    time_el = node.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    span = node.at_css('[class*="date"], [class*="Date"], .published')
    return Date.parse(span.text.strip) if span
    nil
  rescue ArgumentError, TypeError
    nil
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
    doc.at_css('article, .prose, .post-body, .blog-post, main') || doc.at_css('body')
  end

  def max_pages        = 15   # socket.dev has ~13 pages as of 2026
  def parallel_workers = 2
  def batch_delay      = 3    # Socket rate-limits aggressively
end
