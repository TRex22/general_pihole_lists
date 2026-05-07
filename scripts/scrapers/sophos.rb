# frozen_string_literal: true
# Sophos Threat Research Blog scraper
#
# Discovery: sitemap at https://www.sophos.com/sitemap.xml
#   The listing page (/en-us/blog?page=N) renders its article list entirely
#   client-side (Next.js RSC) — no articles appear in the server-side HTML.
#   The sitemap is the only reliable source of all ~2000+ article URLs.
#
# Dates: extracted from JSON-LD (datePublished) on each article page.
#   Articles older than the cutoff are cached as skipped so they are never
#   re-probed on subsequent runs.
#
# IoC section: no fixed heading — threat indicator tables are scanned directly
#   via the scan_extra hook.

class SophosScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Sophos Threat Research'
  SOURCE_KEY  = 'sophos'
  BASE_URL    = 'https://www.sophos.com'
  SITEMAP_URL = 'https://www.sophos.com/sitemap.xml'

  private

  # Replaces paginated listing with sitemap-based discovery.
  def collect_article_urls
    puts "Fetching Sophos sitemap (#{SITEMAP_URL})..."
    resp = fetch_with_retry(SITEMAP_URL)
    unless resp
      puts '  -> Sitemap fetch failed — cannot collect articles.'
      return []
    end

    xml      = Nokogiri::XML(resp.body)
    all_urls = xml.css('url loc').map(&:text)
                  .select { |u| u.match?(%r{/en-us/blog/[^/]+\z}) }
    puts "  -> #{all_urls.size} blog post URLs in sitemap"

    new_urls = all_urls.reject { |u| @cache['articles'][u] }
    puts "  -> #{new_urls.size} not yet cached"

    new_urls.map { |u| { url: u, title: nil, date_str: nil, date: nil } }
  end

  # Fetches each article, extracts date from JSON-LD, skips if before cutoff,
  # then extracts IoCs from text, IoC sections, and threat-indicator tables.
  def scrape_article(article)
    url  = article[:url]
    resp = fetch_with_retry(url)
    unless resp
      @mutex.synchronize { puts "  [FAILED  ] #{url}" }
      return
    end

    doc    = Nokogiri::HTML(resp.body)
    date   = extract_jsonld_date(doc)
    cutoff = Date.today << ((@years || DEFAULT_YEARS) * 12)

    if date && date < cutoff
      @mutex.synchronize do
        @cache['articles'][url] = {
          'url'                  => url,
          'date'                 => date.to_s,
          'scraped_at'           => Time.now.utc.iso8601,
          'domains'              => [],
          'images'               => [],
          'written_to_blocklist' => true,
          'skipped_too_old'      => true
        }
        puts "  [TOO OLD ] #{url} (#{date})"
      end
      return
    end

    title   = doc.at_css('h1')&.text&.strip
    domains = Set.new
    ips     = Set.new
    content = article_content(doc)
    scan_for_iocs(content&.text.to_s, domains, ips)

    ioc_text = extract_ioc_section(doc, headings: ioc_headings)
    scan_for_iocs(ioc_text.to_s, domains, ips, plain_text: true)

    scan_extra(doc, url, domains, ips)

    images   = extract_images(doc, url)
    ocr_doms = extract_domains_from_images(images)
    domains.merge(ocr_doms)

    all_found = (domains.to_a + ips.to_a).sort.uniq

    entry = {
      'url'                  => url,
      'title'                => title,
      'date'                 => date&.to_s,
      'scraped_at'           => Time.now.utc.iso8601,
      'domains'              => all_found,
      'images'               => images,
      'image_ocr_domains'    => ocr_doms.to_a.sort,
      'images_ocr_at'        => (images.any? && ocr_backend && !@skip_ocr ? Time.now.utc.iso8601 : nil),
      'written_to_blocklist' => false
    }

    @mutex.synchronize do
      @cache['articles'][url] = entry
      label = all_found.any? ? "[FOUND #{all_found.size.to_s.rjust(3)}]" : '[NO DOMAINS ]'
      puts "  #{label} #{url}"
      all_found.each { |d| puts "               #{d}" }
      puts "               (#{images.size} image(s), #{ocr_doms.size} via OCR)" if images.any?
      @pending[url] = { domains: all_found, title: title, date: date&.to_s } if all_found.any?
    end
  end

  # Pull datePublished from the first matching Article node in JSON-LD.
  def extract_jsonld_date(doc)
    doc.css('script[type="application/ld+json"]').each do |s|
      data  = JSON.parse(s.text)
      nodes = data.is_a?(Hash) && data['@graph'] ? data['@graph'] : [data]
      nodes.each do |node|
        next unless node.is_a?(Hash)
        date_str = node['datePublished']
        next unless date_str.is_a?(String)
        return Date.parse(date_str)
      end
    rescue JSON::ParserError, ArgumentError
      nil
    end
    nil
  end

  def ioc_headings
    IOC_HEADINGS + %w[
      threat\ indicators
      threat\ indicator
      indicators
      ioc
      iocs
      network\ iocs
      file\ indicators
      malicious\ domains
      c2\ servers
      appendix
    ]
  end

  # Scans tables whose column headers suggest threat-indicator content using
  # plain_text mode, catching non-defanged IPs and domains Sophos may publish.
  def scan_extra(doc, _url, domains, ips)
    doc.css('table').each do |table|
      header_text = table.css('th').map { |th| th.text.strip.downcase }.join(' ')
      next unless header_text.match?(/domain|ip[\s_-]?address|indicator|host(?:name)?|c2|command[\s_-]and[\s_-]control/)
      table.css('td').each do |td|
        scan_for_iocs(td.text.strip, domains, ips, plain_text: true)
      end
    end
  end

  def article_content(doc)
    doc.at_css('.article-body, .blog-post__content, .blog-content, .post-content, [class*="blog-body"], article, main') ||
      doc.at_css('body')
  end

  # Unused — collect_article_urls bypasses pagination entirely, but
  # StandardPaginatedScraper requires these to be defined.
  def listing_url(page) = "#{BASE_URL}/en-us/blog?page=#{page}"
  def parse_listing(_doc) = []

  # Higher concurrency is safe here since the rate limiter caps actual req/s.
  def parallel_workers   = DEFAULT_PARALLEL
  def batch_delay        = 0
  def listing_page_delay = 0
end
