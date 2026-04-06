# frozen_string_literal: true
# any.run public submissions scraper
# Fetches public sandbox submission reports, filtering to suspicious/malicious only.
# Extracts domains contacted during dynamic analysis (not from screenshots).
# Pagination: https://app.any.run/submissions?page=N

ANYRUN_BASE        = 'https://app.any.run'
ANYRUN_SUBMISSIONS = "#{ANYRUN_BASE}/submissions"
# any.run also has a public API for report details
ANYRUN_API_BASE    = "#{ANYRUN_BASE}/api/v1"

class AnyRunScraper < StandardPaginatedScraper
  SOURCE_NAME = 'any.run Submissions'
  SOURCE_KEY  = 'anyrun'
  BASE_URL    = ANYRUN_BASE

  # No images to OCR for any.run — domains come from network analysis data
  def extract_images(_doc, _url) = []

  private

  def listing_url(page)
    page == 1 ? ANYRUN_SUBMISSIONS : "#{ANYRUN_SUBMISSIONS}?page=#{page}"
  end

  def parse_listing(doc)
    entries = []
    # Look for submission links / task IDs
    doc.css('a[href*="/tasks/"], a[href*="/submissions/"]').each do |link|
      href = link['href']
      href = href.start_with?('http') ? href : "#{ANYRUN_BASE}#{href}"
      next if entries.any? { |e| e[:url] == href }

      # Check verdict labels on surrounding element
      parent_text = (link.parent&.text || '').downcase
      verdict     = link.ancestors.take(5).map(&:text).join(' ').downcase
      # Only include suspicious or malicious
      next unless verdict.include?('malicious') || verdict.include?('suspicious') ||
                  parent_text.include?('malicious') || parent_text.include?('suspicious')

      title = link.text.strip
      entries << { url: href, title: title, date_str: nil, date: nil }
    end
    entries
  end

  def scrape_article(article)
    url  = article[:url]
    resp = fetch_with_retry(url)
    unless resp
      @mutex.synchronize { puts "  [FAILED  ] #{url}" }
      return
    end

    doc     = Nokogiri::HTML(resp.body)
    domains = Set.new
    ips     = Set.new

    # any.run shows network connections in specific sections
    content = doc.at_css('.network-section, .dns-requests, .connections, [class*="network"]') ||
              doc.at_css('body')
    scan_for_iocs(content&.text.to_s, domains, ips, plain_text: true)

    # Also scan the full page text
    scan_for_iocs(doc.text, domains, ips)

    all_found = (domains.to_a + ips.to_a).sort.uniq

    entry = {
      'url'                  => url,
      'title'                => article[:title] || doc.at_css('h1')&.text&.strip,
      'date'                 => article[:date_str],
      'scraped_at'           => Time.now.utc.iso8601,
      'domains'              => all_found,
      'images'               => [],
      'image_ocr_domains'    => [],
      'images_ocr_at'        => nil,
      'written_to_blocklist' => false
    }

    @mutex.synchronize do
      @cache['articles'][url] = entry
      label = all_found.any? ? "[FOUND #{all_found.size.to_s.rjust(3)}]" : '[NO DOMAINS ]'
      puts "  #{label} #{url}"
      all_found.each { |d| puts "               #{d}" }
      @pending[url] = { domains: all_found, title: entry['title'], date: article[:date_str] } if all_found.any?
    end
  end
end
