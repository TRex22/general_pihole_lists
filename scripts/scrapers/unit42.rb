# frozen_string_literal: true
# Palo Alto Unit 42 scraper
# Article listing via WordPress AJAX (admin-ajax.php, action=allarticlesloadmore)
# The nonce must be scraped from the listing page before making AJAX calls.
# IoC section: "IP Addresses and Domains" at end of articles.
# Images: https://unit42.paloaltonetworks.com/wp-content/uploads/...

UNIT42_BASE_URL       = 'https://unit42.paloaltonetworks.com'
UNIT42_LISTING_URL    = "#{UNIT42_BASE_URL}/unit-42-all-articles/"
UNIT42_AJAX_URL       = "#{UNIT42_BASE_URL}/wp-admin/admin-ajax.php"
UNIT42_POSTS_PER_PAGE = 12

class Unit42Scraper < StandardPaginatedScraper
  SOURCE_NAME = 'Palo Alto Unit 42'
  SOURCE_KEY  = 'unit42'
  BASE_URL    = UNIT42_BASE_URL

  private

  # Override collect_article_urls to use AJAX pagination
  def collect_article_urls
    articles     = []
    seen         = Set.new
    cutoff       = Date.today << ((@years || DEFAULT_YEARS) * 12)
    last_date    = most_recent_cached_date
    incremental  = @years.nil? && !last_date.nil?
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
      new_count   = 0
      hit_cutoff  = false

      entries.each do |entry|
        next if seen.include?(entry[:url])
        seen.add(entry[:url])

        date = entry[:date]
        if date && date < cutoff
          hit_cutoff = true
          break
        end
        oldest_date = date if date && (oldest_date.nil? || date < oldest_date)
        next if @cache['articles'][entry[:url]]
        articles << entry
        new_count += 1
      end

      puts "  -> #{new_count} new (total #{articles.size})"
      break if hit_cutoff

      if incremental && oldest_date
        if oldest_date < (last_date || Date.today)
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

    nonce = resp.body[/nonce['":\s]+([a-f0-9]{10,})/i, 1] ||
            resp.body[/allarticles[^}]*nonce['":\s]+([a-f0-9]{10,})/i, 1]

    max_pages = resp.body[/max_num_pages['":\s]+(\d+)/i, 1]&.to_i || 90

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

    html = resp.body
    doc  = Nokogiri::HTML(html)
    entries = []
    doc.css('a[href*="unit42.paloaltonetworks.com"]').each do |link|
      href  = link['href']
      title = link.text.strip
      entries << { url: href, title: title, date_str: nil, date: nil }
    end
    # Also grab any relative hrefs to articles
    doc.css('article a, h2 a, h3 a').each do |link|
      href = link['href']
      next unless href
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      next if entries.any? { |e| e[:url] == href }
      entries << { url: href, title: link.text.strip, date_str: nil, date: nil }
    end
    entries
  rescue StandardError => e
    warn "  Unit42 AJAX error page #{page}: #{e.message}"
    nil
  end

  def listing_url(page)
    page == 1 ? UNIT42_LISTING_URL : "#{UNIT42_LISTING_URL}page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    doc.css('article a, h2 a, h3 a').each do |link|
      href = link['href']
      next unless href
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      next unless href.include?(BASE_URL)
      title = link.text.strip
      articles << { url: href, title: title, date_str: nil, date: nil }
    end
    articles.uniq { |a| a[:url] }
  end

  def ioc_headings
    IOC_HEADINGS + ['ip addresses and domains', 'network indicators', 'domains and ips', 'iocs']
  end

  def article_content(doc)
    doc.at_css('.entry-content, article, main') || doc.at_css('body')
  end
end
