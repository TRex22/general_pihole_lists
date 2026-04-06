# frozen_string_literal: true
# Proofpoint Threat Insight scraper
# Uses Algolia search API for article listing (no HTML pagination).
# API key and app ID are public read-only values embedded in the page JS.
# Category filter: search_api_language:en AND category:10346 (threat-insight)
# Images: proofpoint.com/sites/default/files/inline-images/

PROOFPOINT_ALGOLIA_APP_ID  = 'UVWAXG6FKN'
PROOFPOINT_ALGOLIA_API_KEY = '799411b73476846aa4902995845c8096'
PROOFPOINT_ALGOLIA_URL     = "https://#{PROOFPOINT_ALGOLIA_APP_ID.downcase}-dsn.algolia.net/1/indexes/*/queries"
PROOFPOINT_HITS_PER_PAGE   = 20

class ProofpointScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Proofpoint Threat Insight'
  SOURCE_KEY  = 'proofpoint'
  BASE_URL    = 'https://www.proofpoint.com'

  private

  def collect_article_urls
    articles    = []
    seen        = Set.new
    cutoff      = Date.today << ((@years || DEFAULT_YEARS) * 12)
    total_pages = nil

    puts "Collecting Proofpoint articles via Algolia API..."

    page = 0
    loop do
      puts "  Page #{page + 1}#{total_pages ? "/#{total_pages}" : ''}"

      data = fetch_algolia_page(page)
      unless data
        puts "  -> Algolia request failed"
        break
      end

      hits       = data.dig('results', 0, 'hits') || []
      nb_pages   = data.dig('results', 0, 'nbPages') || 1
      total_pages ||= nb_pages

      break if hits.empty?

      hit_cutoff = false
      hits.each do |hit|
        url   = hit['url'] || hit['path']
        next unless url
        url = url.start_with?('http') ? url : "#{BASE_URL}#{url}"
        next if seen.include?(url)
        seen.add(url)

        date = parse_algolia_date(hit)
        if date && date < cutoff
          hit_cutoff = true
          break
        end

        next if @cache['articles'][url]
        title = hit['title'] || hit['post_title']
        articles << { url: url, title: title, date_str: date&.to_s, date: date }
      end

      puts "  -> #{articles.size} total queued"
      break if hit_cutoff || page + 1 >= nb_pages

      page += 1
      sleep 0.5
    end

    articles
  end

  def fetch_algolia_page(page)
    payload = JSON.generate({
      requests: [{
        indexName:             'blog',
        distinct:              true,
        facetingAfterDistinct: true,
        filters:               'search_api_language:en AND category:10346',
        highlightPostTag:      '__/ais-highlight__',
        highlightPreTag:       '__ais-highlight__',
        hitsPerPage:           PROOFPOINT_HITS_PER_PAGE,
        page:                  page,
        query:                 ''
      }]
    })

    resp = HTTParty.post(
      PROOFPOINT_ALGOLIA_URL,
      body:    payload,
      headers: {
        'User-Agent'               => 'Mozilla/5.0 (compatible; pihole-list-builder/1.0)',
        'Accept'                   => 'application/json',
        'content-type'             => 'text/plain',
        'x-algolia-api-key'        => PROOFPOINT_ALGOLIA_API_KEY,
        'x-algolia-application-id' => PROOFPOINT_ALGOLIA_APP_ID,
        'Origin'                   => BASE_URL,
        'Referer'                  => "#{BASE_URL}/"
      },
      timeout: 30
    )
    return nil unless resp.success?
    JSON.parse(resp.body)
  rescue StandardError => e
    warn "  Proofpoint Algolia error: #{e.message}"
    nil
  end

  def parse_algolia_date(hit)
    ts = hit['date'] || hit['post_date'] || hit['created']
    return nil unless ts
    ts.is_a?(Integer) ? Time.at(ts).to_date : Date.parse(ts.to_s)
  rescue ArgumentError
    nil
  end

  def listing_url(page)
    "#{BASE_URL}/en-us/threat-insight?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    doc.css('article, .views-row, .field-content').each do |art|
      link = art.at_css('a[href*="proofpoint.com"]') || art.at_css('h2 a, h3 a')
      next unless link
      href  = link['href']
      href  = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      title = link.text.strip
      articles << { url: href, title: title, date_str: nil, date: nil }
    end
    articles
  end

  def ioc_headings
    IOC_HEADINGS + ['iocs', 'indicators', 'sending domains', 'malicious domains']
  end
end
