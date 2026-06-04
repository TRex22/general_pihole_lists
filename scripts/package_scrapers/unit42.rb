# frozen_string_literal: true
# Palo Alto Unit 42 package scraper — uses WordPress REST API.
# Falls back to HTML pagination when REST API is unavailable.

PKG_UNIT42_BASE     = 'https://unit42.paloaltonetworks.com'
PKG_UNIT42_REST_URL = "#{PKG_UNIT42_BASE}/wp-json/wp/v2/posts"
PKG_UNIT42_PER_PAGE = 12

class PackageUnit42Scraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Palo Alto Unit 42 (packages)'
  SOURCE_KEY  = 'unit42'
  BASE_URL    = PKG_UNIT42_BASE

  private

  def collect_article_urls
    articles = collect_via_rest_api
    articles || []
  end

  def collect_via_rest_api
    cutoff      = Date.today << ((@years || PKG_DEFAULT_YEARS) * 12)
    last_date   = most_recent_cached_date
    incremental = @years.nil? && !last_date.nil?
    articles    = []
    seen        = Set.new
    pages_beyond = 0
    page        = 1

    puts "  Unit 42 WordPress REST API..."

    loop do
      url  = "#{PKG_UNIT42_REST_URL}?per_page=#{PKG_UNIT42_PER_PAGE}&page=#{page}&_fields=link,title,date&orderby=date&order=desc"
      resp = fetch_with_retry(url)
      return nil unless resp&.code == 200

      posts = JSON.parse(resp.body) rescue nil
      return nil unless posts.is_a?(Array)
      break if posts.empty?

      puts "  Page #{page}: #{posts.size} posts"

      hit_cutoff  = false
      oldest_date = nil

      posts.each do |post|
        url_str = post['link'].to_s
        next if url_str.empty? || seen.include?(url_str)
        seen.add(url_str)

        date = (Date.parse(post['date'].to_s) rescue nil)
        oldest_date = date if date && (oldest_date.nil? || date < oldest_date)

        if date && date < cutoff
          hit_cutoff = true
          break
        end

        next if @cache['articles'][url_str]

        raw_title = post.dig('title', 'rendered').to_s
        title     = Nokogiri::HTML(raw_title).text.strip
        articles << { url: url_str, title: title, date: date, date_str: date&.to_s }
      end

      puts "  -> #{articles.size} total"
      break if hit_cutoff || (oldest_date && oldest_date < cutoff)

      if incremental && oldest_date && last_date && oldest_date < last_date
        pages_beyond += 1
        break if pages_beyond >= @pages_back
      end

      page += 1
      sleep 0.3
    end

    articles
  end

  def listing_url(page)
    "#{PKG_UNIT42_BASE}/unit-42-all-articles/#{page > 1 ? "page/#{page}/" : ''}"
  end

  def parse_listing(doc)
    articles = []
    doc.css('article a, h2 a, h3 a').each do |link|
      href = link['href'].to_s
      next unless href.include?(PKG_UNIT42_BASE)
      next if href.match?(%r{/(tag|category|author)/})
      articles << { url: href, title: link.text.strip, date: nil, date_str: nil }
    end
    articles
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
    doc.at_css('.entry-content, article, main') || doc.at_css('body')
  end
end
