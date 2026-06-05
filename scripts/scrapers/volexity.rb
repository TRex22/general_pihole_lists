# frozen_string_literal: true
# Volexity scraper
#
# Uses the WordPress REST API.
# Confirmed: volexity.com/wp-json/wp/v2/posts returns date/link/title.
# Posts follow pattern: /blog/YYYY/MM/DD/slug/

VOLEXITY_BASE     = 'https://www.volexity.com'
VOLEXITY_REST_URL = "#{VOLEXITY_BASE}/wp-json/wp/v2/posts"
VOLEXITY_PER_PAGE = 20

class VolexityScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Volexity'
  SOURCE_KEY  = 'volexity'
  BASE_URL    = VOLEXITY_BASE

  private

  def collect_article_urls
    articles     = []
    seen         = Set.new
    cutoff       = Date.today << ((@years || DEFAULT_YEARS) * 12)
    last_date    = most_recent_cached_date
    incremental  = @years.nil? && !last_date.nil?
    pages_beyond = 0
    page         = 1

    puts "  Volexity WordPress REST API..."

    loop do
      url = "#{VOLEXITY_REST_URL}?per_page=#{VOLEXITY_PER_PAGE}&page=#{page}" \
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
        next if @cache['articles'][url_str]

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

  def listing_url(page) = "#{VOLEXITY_BASE}/blog/"
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
