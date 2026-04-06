# frozen_string_literal: true
# any.run Cybersecurity Blog scraper
# Uses WordPress REST API — no JS rendering needed.
# Blog: https://any.run/cybersecurity-blog/
# API:  https://any.run/cybersecurity-blog/wp-json/wp/v2/posts
# Extracts IOC domains/IPs from blog post content.

require 'json'

ANYRUN_BLOG_BASE = 'https://any.run'
ANYRUN_BLOG_PATH = '/cybersecurity-blog'
ANYRUN_REST_URL  = "#{ANYRUN_BLOG_BASE}#{ANYRUN_BLOG_PATH}/wp-json/wp/v2/posts"
ANYRUN_PER_PAGE  = 12

class AnyRunScraper < StandardPaginatedScraper
  SOURCE_NAME = 'any.run Blog'
  SOURCE_KEY  = 'anyrun'
  BASE_URL    = ANYRUN_BLOG_BASE

  private

  def collect_article_urls
    cutoff       = Date.today << ((@years || DEFAULT_YEARS) * 12)
    last_date    = most_recent_cached_date
    incremental  = @years.nil? && !last_date.nil?
    articles     = []
    seen         = Set.new
    pages_beyond = 0
    page         = 1

    loop do
      url  = "#{ANYRUN_REST_URL}?per_page=#{ANYRUN_PER_PAGE}&page=#{page}&_fields=link,title,date&orderby=date&order=desc"
      resp = fetch_with_retry(url)
      break unless resp&.code == 200

      begin
        posts = JSON.parse(resp.body)
      rescue JSON::ParserError
        break
      end
      break unless posts.is_a?(Array) && !posts.empty?

      puts "  Page #{page}: #{posts.size} posts"

      oldest_date = nil
      hit_cutoff  = false

      posts.each do |post|
        raw_link = post['link'].to_s.gsub('\\/', '/')
        url_str  = raw_link.start_with?('http') ? raw_link : "#{ANYRUN_BLOG_BASE}#{raw_link}"
        next if url_str.empty? || seen.include?(url_str)
        seen.add(url_str)

        date = (Date.parse(post['date'].to_s) rescue nil)
        oldest_date = date if date && (oldest_date.nil? || date < oldest_date)

        if date && date < cutoff
          hit_cutoff = true
          break
        end

        next if @cache['articles'][url_str]

        raw_title = post.dig('title', 'rendered') || post['title'].to_s
        title     = Nokogiri::HTML(raw_title).text.strip
        articles << { url: url_str, title: title, date: date, date_str: date&.to_s }
      end

      puts "  -> #{articles.size} total queued"
      break if hit_cutoff || (oldest_date && oldest_date < cutoff)

      if incremental && oldest_date && last_date
        if oldest_date < last_date
          pages_beyond += 1
          break if pages_beyond >= @pages_back
        end
      end

      page += 1
      sleep 0.3
    end

    articles
  end

  def listing_url(page)
    page == 1 ? "#{ANYRUN_BLOG_BASE}#{ANYRUN_BLOG_PATH}/" : "#{ANYRUN_BLOG_BASE}#{ANYRUN_BLOG_PATH}/page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    seen = Set.new
    doc.css('h2 a, h3 a, .entry-title a, .post-title a').each do |link|
      href = link['href'].to_s
      next unless href.include?(ANYRUN_BLOG_PATH)
      next if seen.include?(href)
      seen.add(href)
      articles << { url: href, title: link.text.strip, date_str: nil, date: nil }
    end
    articles
  end

  def ioc_headings
    IOC_HEADINGS + ['ioc', 'iocs', 'indicators', 'network indicators', 'malware analysis',
                    'c2', 'command and control', 'domains', 'urls observed']
  end
end
