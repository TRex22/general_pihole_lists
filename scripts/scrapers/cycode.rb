# frozen_string_literal: true
# Cycode scraper (application security / supply-chain blog)
#
# Uses the WordPress REST API.
# Confirmed: cycode.com/wp-json/wp/v2/posts returns date/link/title (~500 posts, 2026-10).
# Posts follow pattern: /blog/<slug>/

CYCODE_BASE     = 'https://cycode.com'
CYCODE_REST_URL = "#{CYCODE_BASE}/wp-json/wp/v2/posts"
CYCODE_PER_PAGE = 20

class CycodeScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Cycode'
  SOURCE_KEY  = 'cycode'
  BASE_URL    = CYCODE_BASE

  private

  def collect_article_urls
    articles     = []
    seen         = Set.new
    cutoff       = Date.today << ((@years || DEFAULT_YEARS) * 12)
    last_date    = most_recent_cached_date
    incremental  = @years.nil? && !last_date.nil?
    pages_beyond = 0
    page         = 1

    puts "  Cycode WordPress REST API..."

    loop do
      url = "#{CYCODE_REST_URL}?per_page=#{CYCODE_PER_PAGE}&page=#{page}" \
            "&_fields=link,title,date&orderby=date&order=desc"
      resp = fetch_with_retry(url)
      break unless resp&.success?

      posts = JSON.parse(resp.body) rescue nil
      break unless posts.is_a?(Array) && posts.any?

      puts "  Page #{page}: #{posts.size} posts"
      hit_cutoff  = false
      oldest_date = nil

      posts.each do |post|
        url_str = post['link'].to_s.strip
        next if url_str.empty? || seen.include?(url_str)
        seen.add(url_str)

        date = (Date.parse(post['date'].to_s) rescue nil)
        oldest_date = date if date && (oldest_date.nil? || date < oldest_date)
        if date && date < cutoff
          hit_cutoff = true
          break
        end
        next if cached?(url_str)

        title = Nokogiri::HTML(post.dig('title', 'rendered').to_s).text.strip
        articles << { url: url_str, title: title, date: date, date_str: date&.to_s }
      end

      puts "  -> #{articles.size} total"
      break if hit_cutoff || (oldest_date && oldest_date < cutoff)

      if incremental && oldest_date && last_date && oldest_date < last_date
        pages_beyond += 1
        break if pages_beyond >= @pages_back
      end

      total_pages = resp.headers['x-wp-totalpages']&.to_i
      break if total_pages && page >= total_pages

      page += 1
      sleep 0.3
    end

    articles
  end

  def listing_url(page) = "#{CYCODE_BASE}/blog/"
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
    doc.at_css('.entry-content, .post-content, article, main') || doc.at_css('body')
  end
end
