# frozen_string_literal: true
# Check Point Research scraper
#
# Uses the WordPress REST API — no HTML scraping needed.
# Confirmed: research.checkpoint.com/wp-json/wp/v2/posts returns date/link/title.
# X-WP-TotalPages header used to detect last page.

CHECKPOINT_BASE     = 'https://research.checkpoint.com'
CHECKPOINT_REST_URL = "#{CHECKPOINT_BASE}/wp-json/wp/v2/posts"
CHECKPOINT_PER_PAGE = 20

class CheckpointResearchScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Check Point Research'
  SOURCE_KEY  = 'checkpoint_research'
  BASE_URL    = CHECKPOINT_BASE

  private

  def collect_article_urls
    articles     = []
    seen         = Set.new
    cutoff       = Date.today << ((@years || DEFAULT_YEARS) * 12)
    last_date    = most_recent_cached_date
    incremental  = @years.nil? && !last_date.nil?
    pages_beyond = 0
    page         = 1

    puts "  Check Point Research WordPress REST API..."

    loop do
      url = "#{CHECKPOINT_REST_URL}?per_page=#{CHECKPOINT_PER_PAGE}&page=#{page}" \
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

  def listing_url(page) = "#{CHECKPOINT_BASE}/"
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

  # 10 workers: Cloudflare blocks bursts >20, but archive.org handles concurrency fine
  def parallel_workers = [@parallel, 10].min
  def batch_delay      = 2
end
