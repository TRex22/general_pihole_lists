# frozen_string_literal: true
# Cisco Talos Intelligence Blog package scraper (Ghost CMS)
# Pagination: /page/N/ (confirmed working)
# Listing pages carry no dates — probe_page_boundary_date fetches the last
# article on each page to get a boundary date for the cutoff check.
# PackageStandardPaginatedScraper#collect_article_urls calls probe_page_boundary_date
# after processing each page's entries.

class PackageTalosScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Cisco Talos (packages)'
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
      href = link['href'].to_s
      next if href.nil? || href.empty?
      next if href.match?(%r{/author/|/tag/|/category/})
      href  = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      title = link.text.strip
      articles << { url: href, title: title, date_str: nil, date: nil }
    end
    articles
  end

  # Fetch the last article on the listing page to extract its published date.
  # Uses cached date if already known to avoid an extra HTTP request.
  def probe_page_boundary_date(entries)
    last = entries.last
    return nil unless last

    cached = @cache['articles'][last[:url]]
    if cached&.dig('date')
      return Date.parse(cached['date']) rescue nil
    end

    resp = fetch_with_retry(last[:url])
    return nil unless resp

    extract_article_date(Nokogiri::HTML(resp.body))
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
    doc.at_css('.post-content, article, main') || doc.at_css('body')
  end

  def max_pages = 15
end
