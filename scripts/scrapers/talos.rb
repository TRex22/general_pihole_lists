# frozen_string_literal: true
# Cisco Talos Intelligence Blog scraper
# Pagination: https://blog.talosintelligence.com/page/N/
# IoC section: "Indicators of Compromise (IOCs)" at end of articles
# No images to scrape.

class TalosScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Cisco Talos'
  SOURCE_KEY  = 'talos'
  BASE_URL    = 'https://blog.talosintelligence.com'

  private

  def listing_url(page)
    page == 1 ? BASE_URL : "#{BASE_URL}/page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    doc.css('article, .post, .entry').each do |art|
      link = art.at_css('h2 a, h1 a, .entry-title a, a.post-title')
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
    meta = node.at_css('[class*="date"], [class*="time"]')
    return Date.parse(meta.text.strip) if meta
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def ioc_headings
    IOC_HEADINGS + ['iocs', 'indicators', 'coverage', 'domains blocked']
  end

  # No images on Talos
  def extract_images(_doc, _url) = []
end
