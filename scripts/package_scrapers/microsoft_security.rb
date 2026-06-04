# frozen_string_literal: true
# Microsoft Security Blog package scraper
# https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/

PKG_MSFT_LISTING = 'https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence'

class PackageMicrosoftSecurityScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Microsoft Security Blog (packages)'
  SOURCE_KEY  = 'microsoft_security'
  BASE_URL    = 'https://www.microsoft.com'

  private

  def listing_url(page)
    page == 1 ? "#{PKG_MSFT_LISTING}/?sort-by=newest-oldest" :
                "#{PKG_MSFT_LISTING}/?sort-by=newest-oldest&paged=#{page}"
  end

  def parse_listing(doc)
    articles = []
    doc.css('article, .card, .post, [class*="blog-post"]').each do |art|
      link = art.at_css('a[href*="microsoft.com"]') || art.at_css('h2 a, h3 a, .entry-title a')
      next unless link
      href  = link['href'].to_s
      href  = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      title = link.text.strip
      date  = parse_article_date(art)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end
    articles
  end

  def parse_article_date(node)
    time_el = node.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
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
    doc.at_css('.entry-content, article, .post-content, main') || doc.at_css('body')
  end
end
