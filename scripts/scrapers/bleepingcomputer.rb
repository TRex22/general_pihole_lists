# frozen_string_literal: true
# BleepingComputer scraper
# Pagination: https://www.bleepingcomputer.com/page/N/
# Skip articles whose links don't point to bleepingcomputer.com (ads)
# Images hosted on bleepstatic.com
# Domains: both plaintext and defanged — scan IoC sections with plain_text: true

class BleepingComputerScraper < StandardPaginatedScraper
  SOURCE_NAME = 'BleepingComputer'
  SOURCE_KEY  = 'bleepingcomputer'
  BASE_URL    = 'https://www.bleepingcomputer.com'

  private

  def listing_url(page)
    page == 1 ? BASE_URL : "#{BASE_URL}/page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    doc.css('article.bc_news_story, article').each do |art|
      link = art.at_css('a[href]')
      next unless link
      href = link['href']
      # Expand relative URLs
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      # Skip ads — articles not on bleepingcomputer.com
      next unless URI.parse(href).host&.end_with?('bleepingcomputer.com') rescue next

      title = link.text.strip
      date  = parse_article_date(art)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end
    articles
  end

  def parse_article_date(node)
    time_el = node.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    abbr = node.at_css('abbr[title]')
    return Date.parse(abbr['title']) if abbr
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def skip_article?(url)
    uri = URI.parse(url)
    !uri.host&.end_with?('bleepingcomputer.com')
  rescue URI::Error
    true
  end

  def ioc_headings
    super + ['iocs', 'indicators', 'technical details']
  end

  def image_skip_fragments
    super + ['bleepstatic.com/images/site', '/ads/', '/ad-']
  end
end
