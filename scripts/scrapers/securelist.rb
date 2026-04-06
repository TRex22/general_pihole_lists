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
    articles   = []
    seen       = Set.new
    cutoff     = Date.today << ((@years || DEFAULT_YEARS) * 12)
    last_date  = most_recent_cached_date
    incremental = @years.nil? && !last_date.nil?

    categories = discover_categories
    puts "  Scraping #{categories.size} categories: #{categories.join(', ')}"

    categories.each do |cat|
      puts "  Category: #{cat}"
      pages_beyond = 0

      (1..max_pages).each do |page|
        url  = page == 1 ? "#{BASE_URL}/threat-category/#{cat}/" : "#{BASE_URL}/threat-category/#{cat}/page/#{page}/"
        puts "    Page #{page}: #{url}"
        resp = fetch_with_retry(url)
        break unless resp

        doc     = Nokogiri::HTML(resp.body)
        entries = parse_listing(doc)
        break if entries.empty?

        new_count  = 0
        hit_cutoff = false

        entries.each do |entry|
          next if seen.include?(entry[:url])
          seen.add(entry[:url])
          # Listing pages carry no dates — skip per-entry date check here;
          # we probe the last article below instead.
          next if @cache['articles'][entry[:url]]
          articles << entry
          new_count += 1
        end

        # Listing has no dates — probe the last article on the page to get
        # a boundary date so we know when to stop paginating.
        boundary_date = probe_last_article_date(entries)
        if boundary_date
          if boundary_date < cutoff
            hit_cutoff = true
            puts "    -> Cutoff reached (page boundary: #{boundary_date})"
          elsif incremental && boundary_date < last_date
            pages_beyond += 1
            if pages_beyond >= @pages_back
              hit_cutoff = true
              puts "    -> #{@pages_back} overlap page(s) past #{last_date}, stopping."
            end
          end
        end

        puts "    -> #{new_count} new (total #{articles.size})"
        break if hit_cutoff
        sleep 0.5
      end
    end

    puts "  Total articles queued: #{articles.size}"
    articles
  end

  # Fetch the last article on a listing page and extract its published date.
  # Used as a page-level boundary check when listing pages carry no dates.
  def probe_last_article_date(entries)
    last = entries.last
    return nil unless last

    resp = fetch_with_retry(last[:url])
    return nil unless resp

    doc = Nokogiri::HTML(resp.body)

    # <time datetime="2024-03-15T..."> or <time datetime="2024-03-15">
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el

    # Open Graph / article meta tags
    meta = doc.at_css('meta[property="article:published_time"]') ||
           doc.at_css('meta[name="date"]') ||
           doc.at_css('meta[name="publish_date"]')
    return Date.parse(meta['content']) if meta

    nil
  rescue ArgumentError, TypeError
    nil
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

    # The page contains a main listing section AND a "related articles" section
    # (class includes "spacing-t-small") that always shows recently-published
    # articles regardless of which page is being viewed.  Exclude it so that
    # entries.last is truly the oldest article on the current page.
    main_sections = doc.css('section').reject do |s|
      s['class']&.include?('spacing-t-small')
    end

    nodes = main_sections.flat_map { |s| s.css('article').to_a }
    nodes.each do |art|
      link = art.at_css('a.c-card__link') || art.at_css('h2 a, h3 a')
      next unless link
      href = link['href']
      next unless href&.match?(%r{securelist\.com/[^/]+/\d+/})
      href  = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      title = link.text.strip
      # Listing pages carry no article dates — date is probed separately.
      articles << { url: href, title: title, date_str: nil, date: nil }
    end
    articles
  end

  def ioc_headings
    IOC_HEADINGS + ['ioc', 'iocs', 'appendix', 'malicious domains', 'malicious ips']
  end
end
