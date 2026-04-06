# frozen_string_literal: true
# Krebs on Security scraper
# Pagination: https://krebsonsecurity.com/page/N/
# Domains: mostly plaintext, some defanged. Scan IoC sections with plain_text: true.
# Images: krebsonsecurity.com/wp-content/uploads/

class KrebsScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Krebs on Security'
  SOURCE_KEY  = 'krebsonsecurity'
  BASE_URL    = 'https://krebsonsecurity.com'

  private

  def listing_url(page)
    page == 1 ? BASE_URL : "#{BASE_URL}/page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    doc.css('article, .post').each do |art|
      link = art.at_css('h2 a, h1 a, .entry-title a')
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
    span = node.at_css('.entry-date, .post-date, .date')
    return Date.parse(span.text.strip) if span
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def ioc_headings
    super + ['iocs', 'domains', 'domain names used']
  end
end
