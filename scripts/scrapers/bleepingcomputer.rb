# frozen_string_literal: true
# BleepingComputer scraper
# Pagination: https://www.bleepingcomputer.com/news/ (page 1), /news/page/N/ (N≥2)
# Note: /page/N/ and bare homepage both return 404; /news/ is the main listing.
# Articles live at /news/... — use href pattern to identify them.
# Skip ad articles that link outside bleepingcomputer.com.
# Images hosted on bleepstatic.com.
# Domains: both plaintext and defanged — IoC sections scanned with plain_text: true.

class BleepingComputerScraper < StandardPaginatedScraper
  SOURCE_NAME = 'BleepingComputer'
  SOURCE_KEY  = 'bleepingcomputer'
  BASE_URL    = 'https://www.bleepingcomputer.com'

  private

  # Use /news/ for page 1, /news/page/N/ for subsequent pages.
  # The bare homepage and /page/N/ both return 404; /news/ is the main listing.
  def listing_url(page)
    page == 1 ? "#{BASE_URL}/news/" : "#{BASE_URL}/news/page/#{page}/"
  end

  def parse_listing(doc)
    seen     = Set.new
    articles = []

    # Articles appear as <h4> headings whose links point to /news/...
    doc.css('h4').each do |h4|
      link = h4.at_css('a[href]')
      next unless link

      href = link['href']
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"

      # Skip ads — only keep links to bleepingcomputer.com/news/
      begin
        uri = URI.parse(href)
        next unless uri.host&.end_with?('bleepingcomputer.com') && uri.path.start_with?('/news/')
      rescue URI::Error
        next
      end

      next unless seen.add?(href)

      title = link.text.strip
      date  = parse_article_date(h4)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end

    articles
  end

  def parse_article_date(node)
    # Look in the parent container for a time element
    container = node.parent
    time_el   = container&.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def skip_article?(url)
    uri = URI.parse(url)
    !(uri.host&.end_with?('bleepingcomputer.com') && uri.path.start_with?('/news/'))
  rescue URI::Error
    true
  end

  def ioc_headings
    super + ['iocs', 'indicators', 'technical details']
  end

  def image_skip_fragments
    super + ['bleepstatic.com/images/site', '/ads/', '/ad-']
  end

  # BleepingComputer rate-limits aggressive parallel fetches — use 3 workers
  # with a 2-second pause between batches.
  def parallel_workers = 3
  def batch_delay      = 2
end
