# frozen_string_literal: true
# Google Cloud / Mandiant Threat Intelligence Blog package scraper
# Uses the same batchexecute API as the domain scraper counterpart.

PKG_GOOGLE_BASE      = 'https://cloud.google.com'
PKG_GOOGLE_TOPIC     = '/blog/topics/threat-intelligence'
PKG_GOOGLE_BATCH_RPC = 'SQC9mf'
PKG_GOOGLE_PER_PAGE  = 10

class PackageGoogleThreatIntelScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Google Cloud Threat Intelligence (packages)'
  SOURCE_KEY  = 'google_threat_intel'
  BASE_URL    = PKG_GOOGLE_BASE

  private

  def collect_article_urls
    articles     = []
    seen         = Set.new
    cutoff       = Date.today << ((@years || PKG_DEFAULT_YEARS) * 12)
    last_date    = most_recent_cached_date
    incremental  = @years.nil? && !last_date.nil?
    pages_beyond = 0
    page         = 1

    loop do
      puts "  Page #{page}"
      entries = fetch_batch_page(page)
      if entries.nil?
        puts "  -> Batch request failed, stopping."
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

      puts "  -> #{articles.size} total"
      break if hit_cutoff || (oldest_date && oldest_date < cutoff)

      if incremental && oldest_date && last_date && oldest_date < last_date
        pages_beyond += 1
        break if pages_beyond >= @pages_back
      end

      page += 1
      sleep 0.5
    end

    articles
  end

  def fetch_batch_page(page)
    payload_inner = JSON.generate([
      'cloudblog', 'en', nil, nil,
      PKG_GOOGLE_PER_PAGE, page.to_s,
      'article', ['threat-intelligence'], ['58287']
    ])
    f_req = URI.encode_www_form_component(
      JSON.generate([[[PKG_GOOGLE_BATCH_RPC, payload_inner, nil, 'generic']]])
    )
    query = URI.encode_www_form(
      'rpcids'       => PKG_GOOGLE_BATCH_RPC,
      'source-path'  => PKG_GOOGLE_TOPIC,
      'hl'           => 'en-US',
      'soc-app'      => '1',
      'soc-platform' => '1',
      'soc-device'   => '1',
      'rt'           => 'c'
    )
    url = "#{PKG_GOOGLE_BASE}/blog/_/TransformBlogUi/data/batchexecute?#{query}"

    resp = HTTParty.post(
      url,
      body:    "f.req=#{f_req}&at=&",
      headers: {
        'User-Agent'    => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Content-Type'  => 'application/x-www-form-urlencoded;charset=utf-8',
        'Referer'       => "#{PKG_GOOGLE_BASE}/",
        'X-Same-Domain' => '1',
        'Origin'        => PKG_GOOGLE_BASE
      },
      timeout: 30
    )
    return nil unless resp.success?

    json_line = resp.body.lines.find { |l| l.strip.start_with?('[') }
    return [] unless json_line

    outer     = JSON.parse(json_line.strip)
    inner_str = outer.dig(0, 2)
    return [] unless inner_str.is_a?(String)

    inner = JSON.parse(inner_str)
    list  = inner[0]
    return [] unless list.is_a?(Array)

    list.filter_map do |art|
      next unless art.is_a?(Array) && art[7].is_a?(String) && art[7].include?('/blog/')
      url   = art[7]
      title = art[1].to_s.strip
      ts    = art[8]&.first
      date  = ts ? Time.at(ts).utc.to_date : nil
      { url: url, title: title, date: date, date_str: date&.to_s }
    end
  rescue StandardError => e
    warn "  Google batch error: #{e.message}"
    nil
  end

  def listing_url(page)
    "#{PKG_GOOGLE_BASE}#{PKG_GOOGLE_TOPIC}#{page > 1 ? "?page=#{page}" : ''}"
  end

  def parse_listing(doc)
    []  # unused — collect_article_urls overrides
  end

  def article_content(doc)
    doc.at_css('.blog-article__content, article, main') || doc.at_css('body')
  end
end
