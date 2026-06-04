# frozen_string_literal: true
# Socket.dev blog scraper — npm/PyPI malicious package reports
# https://socket.dev/blog
# Every article is about a specific malicious package discovered by Socket.

class SocketDevScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Socket.dev Security Research'
  SOURCE_KEY  = 'socket_dev'
  BASE_URL    = 'https://socket.dev'

  private

  def listing_url(page)
    page == 1 ? "#{BASE_URL}/blog" : "#{BASE_URL}/blog?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('article, .post, [class*="blog-post"], [class*="BlogPost"]').each do |art|
      link = art.at_css('a[href]')
      next unless link

      href = link['href'].to_s
      next if href.empty?
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      next unless href.include?('socket.dev')
      next unless seen.add?(href)

      title = (art.at_css('h1, h2, h3')&.text || link.text).strip
      date  = parse_article_date(art)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end

    # Fallback: any article links in the page
    if articles.empty?
      doc.css('a[href*="/blog/"]').each do |link|
        href = link['href'].to_s
        next if href == "#{BASE_URL}/blog" || href == '/blog'
        href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
        next unless href.match?(%r{socket\.dev/blog/[^/]+\z})
        next unless seen.add?(href)
        articles << { url: href, title: link.text.strip, date_str: nil, date: nil }
      end
    end

    articles
  end

  def parse_article_date(node)
    time_el = node.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el

    meta = node.at_css('[class*="date"], [class*="Date"], .published')
    return Date.parse(meta.text.strip) if meta
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def extract_article_date(doc)
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el

    meta = doc.at_css('meta[property="article:published_time"]') ||
           doc.at_css('meta[name="date"]')
    return Date.parse(meta['content']) if meta

    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('article, .prose, .post-body, .blog-post, main') || doc.at_css('body')
  end

  # Socket blocks aggressive parallel scraping
  def parallel_workers = 2
  def batch_delay      = 3
end
