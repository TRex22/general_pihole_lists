# frozen_string_literal: true
# Palo Alto Unit 42 scraper
# Primary:  WordPress REST API (/wp-json/wp/v2/posts) — no nonce needed
# Fallback: WordPress AJAX (admin-ajax.php, action=allarticlesloadmore) with nonce
# IoC section: "IP Addresses and Domains" / "Network Indicators" at end of articles
# Images: https://unit42.paloaltonetworks.com/wp-content/uploads/...

require 'json'

UNIT42_BASE_URL       = 'https://unit42.paloaltonetworks.com'
UNIT42_LISTING_URL    = "#{UNIT42_BASE_URL}/unit-42-all-articles/"
UNIT42_AJAX_URL       = "#{UNIT42_BASE_URL}/wp-admin/admin-ajax.php"
UNIT42_REST_URL       = "#{UNIT42_BASE_URL}/wp-json/wp/v2/posts"
UNIT42_POSTS_PER_PAGE = 12

class Unit42Scraper < StandardPaginatedScraper
  SOURCE_NAME = 'Palo Alto Unit 42'
  SOURCE_KEY  = 'unit42'
  BASE_URL    = UNIT42_BASE_URL

  private

  def collect_article_urls
    articles = collect_via_rest_api
    unless articles
      puts "  REST API unavailable — trying AJAX fallback..."
      articles = collect_via_ajax
    end
    articles || []
  end

  # ── WordPress REST API ──────────────────────────────────────────────────────

  def collect_via_rest_api
    cutoff      = Date.today << ((@years || DEFAULT_YEARS) * 12)
    last_date   = most_recent_cached_date
    incremental = @years.nil? && !last_date.nil?
    articles    = []
    seen        = Set.new
    pages_beyond = 0
    page        = 1

    puts "  Trying WordPress REST API..."

    loop do
      url  = "#{UNIT42_REST_URL}?per_page=#{UNIT42_POSTS_PER_PAGE}&page=#{page}&_fields=link,title,date&orderby=date&order=desc"
      resp = fetch_with_retry(url)

      unless resp
        puts "  -> REST API request failed (nil response)"
        return nil
      end

      unless resp.code == 200
        puts "  -> REST API returned HTTP #{resp.code}"
        return nil
      end

      begin
        posts = JSON.parse(resp.body)
      rescue JSON::ParserError => e
        puts "  -> REST API response is not JSON (#{e.message[0, 60]})"
        return nil
      end

      unless posts.is_a?(Array)
        # WordPress returns a hash on auth errors, disabled API, etc.
        msg = posts.is_a?(Hash) ? posts['message'] || posts['code'] : posts.class
        puts "  -> REST API returned non-array: #{msg}"
        return nil
      end

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

  # ── WordPress AJAX fallback ─────────────────────────────────────────────────

  def collect_via_ajax
    cutoff       = Date.today << ((@years || DEFAULT_YEARS) * 12)
    last_date    = most_recent_cached_date
    incremental  = @years.nil? && !last_date.nil?
    articles     = []
    seen         = Set.new
    pages_beyond = 0

    puts "Fetching Unit 42 nonce and max_num_pages from listing page..."
    nonce, max_num_pages = fetch_listing_meta
    unless nonce
      puts "  -> Could not fetch nonce — skipping Unit 42"
      return []
    end
    puts "  nonce=#{nonce} max_num_pages=#{max_num_pages}"

    (1..max_num_pages).each do |page|
      puts "  Page #{page}/#{max_num_pages}"
      entries = fetch_ajax_page(page, nonce, max_num_pages)
      if entries.nil?
        puts "  -> AJAX failed, stopping."
        break
      end
      break if entries.empty?

      oldest_date = nil
      hit_cutoff  = false

      entries.each do |entry|
        next if seen.include?(entry[:url])
        seen.add(entry[:url])

        date = entry[:date]
        oldest_date = date if date && (oldest_date.nil? || date < oldest_date)

        if date && date < cutoff
          hit_cutoff = true
          break
        end
        next if @cache['articles'][entry[:url]]
        articles << entry
      end

      puts "  -> #{articles.size} total queued"
      break if hit_cutoff || (oldest_date && oldest_date < cutoff)

      if incremental && oldest_date && last_date
        if oldest_date < last_date
          pages_beyond += 1
          break if pages_beyond >= @pages_back
        end
      end

      sleep 0.5
    end

    articles
  end

  def fetch_listing_meta
    resp = fetch_with_retry(UNIT42_LISTING_URL)
    return [nil, 0] unless resp

    body = resp.body

    # wp_localize_script output — key near allarticlesloadmore action
    nonce = body[/allarticlesloadmore[^}]{0,300}?nonce["'\s:]+([a-z0-9]{8,})/im, 1] ||
            body[/nonce["'\s:]+([a-z0-9]{10,})/i, 1] ||
            body[/data-nonce=["']([a-z0-9]{8,})["']/i, 1]

    max_pages = body[/max_num_pages["'\s:]+(\d+)/i, 1]&.to_i || 90

    [nonce, max_pages]
  end

  def fetch_ajax_page(page, nonce, max_num_pages)
    body = URI.encode_www_form(
      max_num_pages: max_num_pages,
      nonce:         nonce,
      lang:          'en',
      page:          page,
      postsPerPage:  UNIT42_POSTS_PER_PAGE,
      action:        'allarticlesloadmore'
    )
    resp = HTTParty.post(
      UNIT42_AJAX_URL,
      body:    body,
      headers: {
        'User-Agent'       => 'Mozilla/5.0 (compatible; pihole-list-builder/1.0)',
        'Content-Type'     => 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With' => 'XMLHttpRequest',
        'Referer'          => UNIT42_LISTING_URL,
        'Origin'           => UNIT42_BASE_URL
      },
      timeout: 30
    )
    return nil unless resp.success?

    # The AJAX endpoint returns JSON — extract the HTML fragment from it.
    html = begin
      parsed = JSON.parse(resp.body)
      case parsed
      when Hash
        # 'ajax_results' is a status boolean — actual content is in 'html'
        parsed['html'].to_s.then { |s| s.empty? ? nil : s } ||
          parsed.dig('data', 'html').to_s.then { |s| s.empty? ? nil : s } ||
          parsed['data'].to_s
      when String
        parsed
      else
        resp.body
      end
    rescue JSON::ParserError
      resp.body
    end

    doc     = Nokogiri::HTML(html)
    entries = []
    seen    = Set.new

    doc.css('a[href]').each do |link|
      href = link['href'].to_s.strip
      # Skip JSON-escaped remnants, non-HTTP, and non-article URLs
      next if href.include?('\\') || href.include?('"')
      next unless href.start_with?('http')
      next unless href.include?(BASE_URL)
      next if href.match?(%r{/(tag|category|author|search)/})
      next if seen.include?(href)
      seen.add(href)

      title = link.text.strip
      next if title.empty?

      date  = extract_date_near(link)
      entries << { url: href, title: title, date: date, date_str: date&.to_s }
    end

    entries
  rescue StandardError => e
    warn "  Unit42 AJAX error page #{page}: #{e.message}"
    nil
  end

  def extract_date_near(node)
    # Walk up to find a time[datetime] sibling or ancestor
    el = node
    5.times do
      el = el.parent
      break unless el
      time = el.at_css('time[datetime]')
      return (Date.parse(time['datetime']) rescue nil) if time
    end
    nil
  end

  # ── Shared helpers ──────────────────────────────────────────────────────────

  def listing_url(page)
    page == 1 ? UNIT42_LISTING_URL : "#{UNIT42_LISTING_URL}page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    seen = Set.new
    doc.css('article a, h2 a, h3 a').each do |link|
      href = link['href']
      next unless href
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      next unless href.include?(BASE_URL)
      next if seen.include?(href)
      seen.add(href)
      date  = extract_date_near(link)
      title = link.text.strip
      articles << { url: href, title: title, date: date, date_str: date&.to_s }
    end
    articles
  end

  def ioc_headings
    IOC_HEADINGS + ['ip addresses and domains', 'network indicators', 'domains and ips', 'iocs']
  end

  def article_content(doc)
    doc.at_css('.entry-content, article, main') || doc.at_css('body')
  end
end
