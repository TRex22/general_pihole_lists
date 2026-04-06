# frozen_string_literal: true
# Cisco Talos Intelligence Blog scraper (Ghost CMS)
# Pagination: https://blog.talosintelligence.com/page/N/
# IoC section: "Indicators of Compromise (IOCs)" at end of articles
# No images to scrape. Listing pages carry no article dates.

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
    doc.css('.post-wrapper, .post-card').each do |card|
      link = card.at_css('h2 a, h3 a, h1 a')
      next unless link
      href = link['href']
      next if href.nil? || href.empty?
      next if href.match?(%r{/author/|/tag/|/category/})
      href  = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      title = link.text.strip
      # Listing pages carry no dates — probed via probe_page_boundary_date
      articles << { url: href, title: title, date_str: nil, date: nil }
    end
    articles
  end

  # Fetch the last article on a listing page and extract its published date.
  def probe_page_boundary_date(entries)
    last = entries.last
    return nil unless last

    resp = fetch_with_retry(last[:url])
    return nil unless resp

    doc = Nokogiri::HTML(resp.body)

    meta = doc.at_css('meta[property="article:published_time"]')
    return Date.parse(meta['content']) if meta

    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el

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
