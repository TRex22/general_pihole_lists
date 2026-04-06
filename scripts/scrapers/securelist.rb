# frozen_string_literal: true
# Kaspersky Securelist scraper
# Scrapes multiple threat categories, each paginated: /threat-category/X/page/N/
# Scans https://securelist.com/categories/ to discover additional categories.
# Images: media.kasperskycontenthub.com

SECURELIST_BASE = 'https://securelist.com'
SECURELIST_DEFAULT_CATEGORIES = %w[
  apt-targeted-attacks
  secure-environment
  mobile-threats
  spam-and-phishing
  web-threats
  vulnerabilities-and-exploits
].freeze

class SecurelistScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Kaspersky Securelist'
  SOURCE_KEY  = 'securelist'
  BASE_URL    = SECURELIST_BASE

  private

  def listing_url(page)
    # Not used — we iterate categories
    "#{BASE_URL}/page/#{page}/"
  end

  def collect_article_urls
    articles = []
    seen     = Set.new
    cutoff   = Date.today << ((@years || DEFAULT_YEARS) * 12)

    categories = discover_categories
    puts "  Scraping #{categories.size} categories: #{categories.join(', ')}"

    categories.each do |cat|
      puts "  Category: #{cat}"
      (1..max_pages).each do |page|
        url  = page == 1 ? "#{BASE_URL}/threat-category/#{cat}/" : "#{BASE_URL}/threat-category/#{cat}/page/#{page}/"
        puts "    Page #{page}: #{url}"
        resp = fetch_with_retry(url)
        break unless resp

        doc     = Nokogiri::HTML(resp.body)
        entries = parse_listing(doc)
        break if entries.empty?

        hit_cutoff = false
        entries.each do |entry|
          next if seen.include?(entry[:url])
          seen.add(entry[:url])
          date = entry[:date]
          if date && date < cutoff
            hit_cutoff = true
            break
          end
          next if @cache['articles'][entry[:url]]
          articles << entry
        end
        break if hit_cutoff
        sleep 0.5
      end
    end

    puts "  Total articles queued: #{articles.size}"
    articles
  end

  def discover_categories
    resp = fetch_with_retry("#{BASE_URL}/categories/")
    return SECURELIST_DEFAULT_CATEGORIES unless resp

    doc  = Nokogiri::HTML(resp.body)
    cats = doc.css('a[href*="/threat-category/"]').filter_map do |a|
      a['href']&.match(%r{/threat-category/([^/]+)/})&.[](1)
    end.uniq

    cats.empty? ? SECURELIST_DEFAULT_CATEGORIES : cats
  end

  def parse_listing(doc)
    articles = []
    doc.css('article, .post, .entry, .article-item').each do |art|
      link = art.at_css('a[href*="securelist.com"]') || art.at_css('h2 a, h3 a, .title a')
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
    IOC_HEADINGS + ['ioc', 'iocs', 'appendix', 'malicious domains', 'malicious ips']
  end
end
