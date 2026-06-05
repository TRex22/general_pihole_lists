# frozen_string_literal: true
# Palo Alto Unit 42 package scraper
# Primary: WordPress REST API (/wp-json/wp/v2/posts) — confirmed accessible and returning data.
# Article title is in <h4>, not <h2>/<h3>. REST API bypasses HTML parsing entirely.

PKG_UNIT42_BASE     = 'https://unit42.paloaltonetworks.com'
PKG_UNIT42_REST_URL = "#{PKG_UNIT42_BASE}/wp-json/wp/v2/posts"
PKG_UNIT42_PER_PAGE = 20

class PackageUnit42Scraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Palo Alto Unit 42 (packages)'
  SOURCE_KEY  = 'unit42'
  BASE_URL    = PKG_UNIT42_BASE

  private

  def collect_article_urls
    articles    = []
    seen        = Set.new
    cutoff      = Date.today << ((@years || PKG_DEFAULT_YEARS) * 12)
    last_date   = most_recent_cached_date
    incremental = @years.nil? && !last_date.nil?
    pages_beyond = 0
    page        = 1

    puts "  Unit 42 WordPress REST API..."

    loop do
      url  = "#{PKG_UNIT42_REST_URL}?per_page=#{PKG_UNIT42_PER_PAGE}&page=#{page}" \
             "&_fields=link,title,date&orderby=date&order=desc"
      resp = fetch_with_retry(url)
      break unless resp

      # REST API returns 400 when past the last page
      break unless resp.code == 200

      posts = JSON.parse(resp.body) rescue nil
      break unless posts.is_a?(Array) && posts.any?

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

        title = Nokogiri::HTML(post.dig('title', 'rendered').to_s).text.strip
        articles << { url: url_str, title: title, date: date, date_str: date&.to_s }
      end

      puts "  -> #{articles.size} total queued"
      break if hit_cutoff || (oldest_date && oldest_date < cutoff)

      if incremental && oldest_date && last_date
        if @lookback_days&.positive?
          break if oldest_date < (last_date - @lookback_days)
        elsif oldest_date < last_date
          pages_beyond += 1
          break if pages_beyond >= @pages_back
        end
      end

      # WordPress REST API X-WP-TotalPages header
      total_pages = resp.headers['x-wp-totalpages']&.to_i
      break if total_pages && page >= total_pages
      break if page >= 50  # hard cap

      page += 1
      sleep 0.3
    end

    articles
  end

  # Unused — collect_article_urls overrides pagination entirely
  def listing_url(page) = "#{PKG_UNIT42_BASE}/unit-42-all-articles/#{page > 1 ? "page/#{page}/" : ''}"
  def parse_listing(_doc) = []

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
