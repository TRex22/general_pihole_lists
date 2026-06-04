# frozen_string_literal: true
# JFrog Security Research blog scraper
# Tag: /blog/tag/security-research/ — confirmed working, /page/N/ pagination.
# Covers malicious packages (npm, PyPI, Go) plus CVEs and vulnerability research.

JFROG_BASE          = 'https://jfrog.com'
JFROG_SECURITY_TAG  = "#{JFROG_BASE}/blog/tag/security-research"

class JFrogScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'JFrog Security Research'
  SOURCE_KEY  = 'jfrog'
  BASE_URL    = JFROG_BASE

  private

  def listing_url(page)
    page == 1 ? "#{JFROG_SECURITY_TAG}/" : "#{JFROG_SECURITY_TAG}/page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('article, .post, .blog-post').each do |art|
      link = art.at_css('h1 a, h2 a, h3 a, .entry-title a')
      next unless link

      href = link['href'].to_s
      next if href.empty?
      href = href.start_with?('http') ? href : "#{JFROG_BASE}#{href}"
      next unless href.include?('jfrog.com/blog/')
      next unless seen.add?(href)

      title = link.text.strip
      date  = parse_article_date(art)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end

    # Fallback: generic anchor scan
    if articles.empty?
      doc.css('a[href*="/blog/"]').each do |link|
        href = link['href'].to_s
        href = href.start_with?('http') ? href : "#{JFROG_BASE}#{href}"
        next unless href.match?(%r{jfrog\.com/blog/[a-z0-9\-]+/?$})
        next if href.include?('/tag/') || href.include?('/category/')
        next unless seen.add?(href)
        articles << { url: href, title: link.text.strip, date_str: nil, date: nil }
      end
    end

    articles
  end

  def parse_article_date(node)
    time_el = node.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    span = node.at_css('.entry-date, .post-date, .date')
    return Date.parse(span.text.strip) if span
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def extract_article_date(doc)
    meta = doc.at_css('meta[property="article:published_time"]')
    return Date.parse(meta['content']) if meta
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.entry-content, .post-content, article, main') || doc.at_css('body')
  end
end
