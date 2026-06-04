# frozen_string_literal: true
# Snyk Security blog scraper — malicious package research
# https://snyk.io/blog/tag/security-research/
# Covers npm, PyPI, and container supply chain threats.

class SnykScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Snyk Security Research'
  SOURCE_KEY  = 'snyk'
  BASE_URL    = 'https://snyk.io'
  LISTING_BASE = "#{BASE_URL}/blog/tag/security-research"

  private

  def listing_url(page)
    page == 1 ? "#{LISTING_BASE}/" : "#{LISTING_BASE}/page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('article, .post, [class*="BlogCard"], [class*="blog-card"]').each do |art|
      link = art.at_css('h1 a, h2 a, h3 a, [class*="title"] a, a[href*="/blog/"]')
      next unless link

      href = link['href'].to_s
      next if href.empty?
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      next unless href.include?('snyk.io/blog/')
      next unless seen.add?(href)

      title = link.text.strip
      date  = parse_article_date(art)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end

    articles
  end

  def parse_article_date(node)
    time_el = node.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    span = node.at_css('[class*="date"], [class*="Date"]')
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
    doc.at_css('.blog-content, .post-content, .entry-content, article, main') || doc.at_css('body')
  end

  def parallel_workers = 3
  def batch_delay      = 1
end
