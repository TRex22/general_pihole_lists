# frozen_string_literal: true
# Kaspersky Securelist package scraper
# Scrapes "secure-environment" and "web-threats" categories for package-related research.

PKG_SECURELIST_BASE = 'https://securelist.com'
PKG_SECURELIST_CATEGORIES = %w[secure-environment web-threats apt-targeted-attacks].freeze

class PackageSecurelistScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Kaspersky Securelist (packages)'
  SOURCE_KEY  = 'securelist'
  BASE_URL    = PKG_SECURELIST_BASE

  private

  # Overrides standard collect_article_urls to iterate across categories
  def collect_article_urls
    articles   = []
    seen       = Set.new
    cutoff     = Date.today << ((@years || PKG_DEFAULT_YEARS) * 12)
    last_date  = most_recent_cached_date
    incremental = @years.nil? && !last_date.nil?

    PKG_SECURELIST_CATEGORIES.each do |cat|
      puts "  Category: #{cat}"
      pages_beyond = 0

      (1..max_pages).each do |page|
        url  = page == 1 ? "#{PKG_SECURELIST_BASE}/threat-category/#{cat}/" :
                            "#{PKG_SECURELIST_BASE}/threat-category/#{cat}/page/#{page}/"
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
          next if @cache['articles'][entry[:url]]
          articles << entry
          new_count += 1
        end

        boundary = probe_boundary_date(entries)
        if boundary
          if boundary < cutoff
            hit_cutoff = true
          elsif incremental && boundary < last_date
            pages_beyond += 1
            hit_cutoff = true if pages_beyond >= @pages_back
          end
        end

        puts "    -> #{new_count} new (total #{articles.size})"
        break if hit_cutoff
        sleep 0.5
      end
    end

    articles
  end

  def probe_boundary_date(entries)
    last = entries.last
    return nil unless last
    resp = fetch_with_retry(last[:url])
    return nil unless resp
    extract_article_date(Nokogiri::HTML(resp.body))
  end

  def parse_listing(doc)
    articles = []
    main = doc.css('section').reject { |s| s['class']&.include?('spacing-t-small') }
    nodes = main.flat_map { |s| s.css('article').to_a }
    nodes.each do |art|
      link = art.at_css('a.c-card__link') || art.at_css('h2 a, h3 a')
      next unless link
      href = link['href'].to_s
      next unless href.match?(%r{securelist\.com/[^/]+/\d+/})
      href  = href.start_with?('http') ? href : "#{PKG_SECURELIST_BASE}#{href}"
      title = link.text.strip
      articles << { url: href, title: title, date_str: nil, date: nil }
    end
    articles
  end

  def listing_url(page)
    "#{PKG_SECURELIST_BASE}/page/#{page}/"
  end

  def extract_article_date(doc)
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    meta = doc.at_css('meta[property="article:published_time"]')
    return Date.parse(meta['content']) if meta
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.article-body, .entry-content, article, main') || doc.at_css('body')
  end

  def max_pages = 30
end
