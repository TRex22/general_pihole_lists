# frozen_string_literal: true
# Google Cloud / Mandiant Threat Intelligence Blog scraper
# Uses Google's batchexecute API — no session token required.
# Response: )]}'\n\nCHUNK_SIZE\n[["wrb.fr","SQC9mf","<inner-json>",...]...]
# Inner JSON: [[[article_array, ...], ...]]
# Article fields: [0]=category [1]=title [7]=url [8]=[unix_ts_seconds]
# Images: storage.googleapis.com/gweb-cloudblog-publish/

require 'json'

GOOGLE_THREAT_BASE   = 'https://cloud.google.com'
GOOGLE_THREAT_TOPIC  = '/blog/topics/threat-intelligence'
GOOGLE_BATCH_RPC     = 'SQC9mf'
GOOGLE_HITS_PER_PAGE = 10

class GoogleThreatIntelScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Google Cloud Threat Intelligence'
  SOURCE_KEY  = 'google_threat_intel'
  BASE_URL    = GOOGLE_THREAT_BASE

  private

  def collect_article_urls
    articles     = []
    seen         = Set.new
    cutoff       = Date.today << ((@years || DEFAULT_YEARS) * 12)
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

      if incremental && oldest_date && last_date
        if oldest_date < last_date
          pages_beyond += 1
          break if pages_beyond >= @pages_back
        end
      end

      page += 1
      sleep 0.5
    end

    articles
  end

  def fetch_batch_page(page)
    payload_inner = JSON.generate([
      'cloudblog', 'en', nil, nil,
      GOOGLE_HITS_PER_PAGE, page.to_s,
      'article', ['threat-intelligence'], ['58287']
    ])
    f_req = URI.encode_www_form_component(
      JSON.generate([[[GOOGLE_BATCH_RPC, payload_inner, nil, 'generic']]])
    )
    query = URI.encode_www_form(
      'rpcids'       => GOOGLE_BATCH_RPC,
      'source-path'  => GOOGLE_THREAT_TOPIC,
      'hl'           => 'en-US',
      'soc-app'      => '1',
      'soc-platform' => '1',
      'soc-device'   => '1',
      'rt'           => 'c'
    )
    url = "#{BASE_URL}/blog/_/TransformBlogUi/data/batchexecute?#{query}"

    resp = HTTParty.post(
      url,
      body:    "f.req=#{f_req}&at=&",
      headers: {
        'User-Agent'    => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Content-Type'  => 'application/x-www-form-urlencoded;charset=utf-8',
        'Referer'       => "#{BASE_URL}/",
        'X-Same-Domain' => '1',
        'Origin'        => BASE_URL
      },
      timeout: 30
    )
    return nil unless resp.success?

    parse_batch_response(resp.body)
  rescue StandardError => e
    warn "  Google batch error: #{e.message}"
    nil
  end

  def parse_batch_response(body)
    # Find the JSON array line (after the )]}' header and chunk-size line)
    json_line = body.lines.find { |l| l.strip.start_with?('[') }
    return [] unless json_line

    outer     = JSON.parse(json_line.strip)
    inner_str = outer.dig(0, 2)
    return [] unless inner_str.is_a?(String)

    inner = JSON.parse(inner_str)
    list  = inner[0]
    return [] unless list.is_a?(Array)

    entries = []
    list.each do |art|
      next unless art.is_a?(Array) && art[7].is_a?(String)
      url   = art[7]
      next unless url.include?('/blog/')
      title = art[1].to_s.strip
      ts    = art[8]&.first
      date  = ts ? Time.at(ts).utc.to_date : nil
      entries << { url: url, title: title, date: date, date_str: date&.to_s }
    end
    entries
  rescue JSON::ParserError => e
    warn "  Google batch parse error: #{e.message}"
    []
  end

  def listing_url(page)
    page == 1 ? "#{BASE_URL}#{GOOGLE_THREAT_TOPIC}" : "#{BASE_URL}#{GOOGLE_THREAT_TOPIC}?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    seen = Set.new
    doc.css("a[href*=\"/blog/topics/threat-intelligence/\"]").each do |link|
      href = link['href'].to_s
      next if href == "#{BASE_URL}#{GOOGLE_THREAT_TOPIC}"
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      next if seen.include?(href)
      seen.add(href)
      title = link['title'] || link['track-name'] || link.text.strip
      articles << { url: href, title: title, date_str: nil, date: nil }
    end
    articles
  end

  def ioc_headings
    IOC_HEADINGS + ['ioc', 'appendix', 'malware families', 'network indicators']
  end
end
