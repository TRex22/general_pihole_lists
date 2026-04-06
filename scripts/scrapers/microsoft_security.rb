# frozen_string_literal: true
# Microsoft Security Blog scraper
# Pagination: ?sort-by=newest-oldest&paged=N
# IoC section: table entitled "Indicators of compromise" with defanged domains/IPs
# Images: microsoft.com/en-us/security/blog/wp-content/uploads/

MICROSOFT_SECURITY_BASE = 'https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence'

class MicrosoftSecurityScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Microsoft Security Blog'
  SOURCE_KEY  = 'microsoft_security'
  BASE_URL    = 'https://www.microsoft.com'

  private

  def listing_url(page)
    page == 1 ? "#{MICROSOFT_SECURITY_BASE}/?sort-by=newest-oldest" :
                "#{MICROSOFT_SECURITY_BASE}/?sort-by=newest-oldest&paged=#{page}"
  end

  def parse_listing(doc)
    articles = []
    doc.css('article, .card, .post, [class*="blog-post"]').each do |art|
      link = art.at_css('a[href*="microsoft.com"]') || art.at_css('h2 a, h3 a, .entry-title a')
      next unless link
      href  = link['href']
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

  def ioc_headings
    IOC_HEADINGS + ['indicators of compromise (iocs)', 'ioc table', 'appendix']
  end

  def article_content(doc)
    doc.at_css('.entry-content, article, .post-content, main') || doc.at_css('body')
  end
end
