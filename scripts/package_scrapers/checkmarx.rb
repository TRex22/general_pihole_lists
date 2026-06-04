# frozen_string_literal: true
# Checkmarx Supply Chain Security blog scraper
# Uses the WordPress REST API (wp-json/wp/v2/posts) filtered to the
# "Supply Chain Security" category (id: 844).
# API confirmed at: checkmarx.com/wp-json/wp/v2/posts

CHECKMARX_BASE         = 'https://checkmarx.com'
CHECKMARX_REST_URL     = "#{CHECKMARX_BASE}/wp-json/wp/v2/posts"
CHECKMARX_CATEGORY_ID  = 844   # Supply Chain Security
CHECKMARX_PER_PAGE     = 20

class CheckmarxScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Checkmarx Supply Chain Security'
  SOURCE_KEY  = 'checkmarx'
  BASE_URL    = CHECKMARX_BASE

  private

  def collect_article_urls
    articles    = []
    seen        = Set.new
    cutoff      = Date.today << ((@years || PKG_DEFAULT_YEARS) * 12)
    last_date   = most_recent_cached_date
    incremental = @years.nil? && !last_date.nil?
    pages_beyond = 0
    page        = 1

    puts "  Checkmarx WordPress REST API (category: supply-chain-security)..."

    loop do
      url = "#{CHECKMARX_REST_URL}?per_page=#{CHECKMARX_PER_PAGE}&page=#{page}" \
            "&categories=#{CHECKMARX_CATEGORY_ID}&_fields=link,title,date&orderby=date&order=desc"

      resp = fetch_with_retry(url)
      break unless resp&.success?

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

      puts "  -> #{articles.size} total"
      break if hit_cutoff || (oldest_date && oldest_date < cutoff)

      if incremental && oldest_date && last_date && oldest_date < last_date
        pages_beyond += 1
        break if pages_beyond >= @pages_back
      end

      # WordPress REST API sends X-WP-TotalPages header
      total_pages = resp.headers['x-wp-totalpages']&.to_i
      break if total_pages && page >= total_pages

      page += 1
      sleep 0.3
    end

    articles
  end

  def listing_url(page) = "#{CHECKMARX_BASE}/blog/page/#{page}/"
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
