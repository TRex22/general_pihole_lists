# frozen_string_literal: true
# Aqua Security (Team Nautilus) blog scraper
# https://www.aquasec.com/blog/category/supply-chain-security/
# Covers malicious packages in npm, PyPI, RubyGems, and container images.

class AquaSecurityScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Aqua Security (Team Nautilus)'
  SOURCE_KEY  = 'aqua_security'
  BASE_URL    = 'https://www.aquasec.com'
  LISTING_BASE = "#{BASE_URL}/blog/category/supply-chain-security"

  private

  def listing_url(page)
    page == 1 ? "#{LISTING_BASE}/" : "#{LISTING_BASE}/page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('article, .post, .blog-post, [class*="BlogPost"]').each do |art|
      link = art.at_css('h1 a, h2 a, h3 a, .entry-title a')
      next unless link

      href = link['href'].to_s
      next if href.empty?
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      next unless href.include?('aquasec.com')
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
