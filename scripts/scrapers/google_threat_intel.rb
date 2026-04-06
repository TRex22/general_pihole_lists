# frozen_string_literal: true
# Google Cloud / Mandiant Threat Intelligence Blog scraper
# Uses Google's batchexecute API for article listing.
# The f.sid session token must be fetched from the listing page first.
# Articles may have IoC sections; may also have code blocks with curl examples containing hxxp:// domains.
# Images: storage.googleapis.com/gweb-cloudblog-publish/

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
    articles = []
    seen     = Set.new
    cutoff   = Date.today << ((@years || DEFAULT_YEARS) * 12)

    puts "Fetching Google Cloud blog session token..."
    sid, bl = fetch_session_params
    unless sid
      puts "  -> Could not get session token — trying direct HTML pagination"
      return collect_via_html_pagination(articles, seen, cutoff)
    end
    puts "  sid=#{sid}"

    page = 1
    loop do
      puts "  Page #{page}"
      entries = fetch_batch_page(page, sid, bl)
      if entries.nil?
        puts "  -> Batch request failed, falling back to HTML"
        return collect_via_html_pagination(articles, seen, cutoff)
      end
      break if entries.empty?

      hit_cutoff = false
      entries.each do |entry|
        next if seen.include?(entry[:url])
        seen.add(entry[:url])
        date = entry[:date]
        if date && date < cutoff
          hit_cutoff = true
          break
        end
        next if @cache['articles'][entry[:url]]
        articles << entry
      end
      puts "  -> #{articles.size} total"
      break if hit_cutoff
      page += 1
      sleep 0.5
    end

    articles
  end

  def fetch_session_params
    resp = fetch_with_retry("#{BASE_URL}#{GOOGLE_THREAT_TOPIC}")
    return [nil, nil] unless resp

    sid = resp.body[/f\.sid=(-?\d+)/i, 1]
    bl  = resp.body[/"bl":"([^"]+)"/i, 1] || resp.body[/bl=([a-z0-9_-]+)/i, 1]
    [sid, bl]
  end

  def fetch_batch_page(page, sid, bl)
    # Build the f.req payload encoding
    payload_inner = JSON.generate(['cloudblog', 'en', nil, nil, GOOGLE_HITS_PER_PAGE, page.to_s, 'article', ['threat-intelligence'], ['58287']])
    f_req = URI.encode_www_form_component(JSON.generate([[[GOOGLE_BATCH_RPC, payload_inner, nil, 'generic']]]))

    query_params = URI.encode_www_form(
      'rpcids'       => GOOGLE_BATCH_RPC,
      'source-path'  => GOOGLE_THREAT_TOPIC,
      'hl'           => 'en-US',
      'soc-app'      => '1',
      'soc-platform' => '1',
      'soc-device'   => '1',
      'rt'           => 'c'
    )
    query_params += "&f.sid=#{sid}&bl=#{bl}" if sid

    url  = "#{BASE_URL}/blog/_/TransformBlogUi/data/batchexecute?#{query_params}"
    body = "f.req=#{f_req}&at=&"

    resp = HTTParty.post(
      url,
      body:    body,
      headers: {
        'User-Agent'    => 'Mozilla/5.0 (compatible; pihole-list-builder/1.0)',
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
    entries = []
    # The response is a series of JSON-encoded chunks prefixed with length
    body.scan(/"url"\s*:\s*"([^"]+)"[^}]*"title"\s*:\s*"([^"]+)"/i) do |url, title|
      url = url.gsub('\\/', '/')
      url = url.start_with?('http') ? url : "#{BASE_URL}#{url}"
      entries << { url: url, title: title, date_str: nil, date: nil }
    end
    # Also try to find blog post links
    body.scan(%r{"(#{Regexp.escape(BASE_URL)}/blog/[^"]+)"}) do |m|
      url = m[0]
      next if entries.any? { |e| e[:url] == url }
      entries << { url: url, title: '', date_str: nil, date: nil }
    end
    entries
  end

  def collect_via_html_pagination(articles, seen, cutoff)
    (1..max_pages).each do |page|
      url  = page == 1 ? "#{BASE_URL}#{GOOGLE_THREAT_TOPIC}" : "#{BASE_URL}#{GOOGLE_THREAT_TOPIC}/page/#{page}"
      puts "  HTML page #{page}: #{url}"
      resp = fetch_with_retry(url)
      break unless resp
      doc     = Nokogiri::HTML(resp.body)
      entries = parse_listing(doc)
      break if entries.empty?
      entries.each do |entry|
        next if seen.include?(entry[:url])
        seen.add(entry[:url])
        date = entry[:date]
        break if date && date < cutoff
        next if @cache['articles'][entry[:url]]
        articles << entry
      end
      sleep 0.5
    end
    articles
  end

  def listing_url(page)
    page == 1 ? "#{BASE_URL}#{GOOGLE_THREAT_TOPIC}" : "#{BASE_URL}#{GOOGLE_THREAT_TOPIC}/page/#{page}"
  end

  def parse_listing(doc)
    articles = []
    doc.css('article a, [class*="blog"] a, .post a').each do |link|
      href = link['href']
      next unless href&.include?('/blog/')
      href  = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      next if articles.any? { |a| a[:url] == href }
      title = link.text.strip
      articles << { url: href, title: title, date_str: nil, date: nil }
    end
    articles
  end

  def ioc_headings
    IOC_HEADINGS + ['ioc', 'appendix', 'malware families', 'network indicators']
  end
end
