# frozen_string_literal: true
# ESET WeLiveSecurity scraper
# Pagination: https://www.welivesecurity.com/en/?page=N
# IoC section: "IoCs" + "Network" subsection (table of IPs and domains)
# Consistent [.] defanging. Images: web-assets.esetstatic.com

class WeLiveSecurityScraper < StandardPaginatedScraper
  SOURCE_NAME = 'ESET WeLiveSecurity'
  SOURCE_KEY  = 'welivesecurity'
  BASE_URL    = 'https://www.welivesecurity.com'

  private

  def listing_url(page)
    page == 1 ? "#{BASE_URL}/en/" : "#{BASE_URL}/en/?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    doc.css('article, .post, .entry, .teaser').each do |art|
      link = art.at_css('a[href*="welivesecurity.com"]') || art.at_css('h2 a, h3 a, .entry-title a')
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
    IOC_HEADINGS + ['ioc', 'iocs', 'network', 'network indicators', 'appendix', 'malware samples']
  end
end
