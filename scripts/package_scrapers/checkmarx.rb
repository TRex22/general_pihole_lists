# frozen_string_literal: true
# Checkmarx Supply Chain Security blog scraper
# https://checkmarx.com/blog/category/supply-chain-security/
# Dedicated supply-chain threat research covering npm, PyPI, NuGet.

class CheckmarxScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Checkmarx Supply Chain Security'
  SOURCE_KEY  = 'checkmarx'
  BASE_URL    = 'https://checkmarx.com'
  LISTING_BASE = "#{BASE_URL}/blog/category/supply-chain-security"

  private

  def listing_url(page)
    page == 1 ? "#{LISTING_BASE}/" : "#{LISTING_BASE}/page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('article, .post, .blog-post, [class*="BlogPost"]').each do |art|
      link = art.at_css('h1 a, h2 a, h3 a, .entry-title a, [class*="title"] a')
      next unless link

      href = link['href'].to_s
      next if href.empty?
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      next unless href.include?('checkmarx.com')
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
    span = node.at_css('.entry-date, .post-date, .date, [class*="date"]')
    return Date.parse(span.text.strip) if span
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def extract_article_date(doc)
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    meta = doc.at_css('meta[property="article:published_time"]')
    return Date.parse(meta['content']) if meta
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.entry-content, .post-content, article, main') || doc.at_css('body')
  end
end
