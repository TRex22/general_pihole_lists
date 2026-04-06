# frozen_string_literal: true
# SANS Internet Storm Center scraper
# Archives by year/month: https://isc.sans.edu/diaryarchive.html?year=YYYY&month=M
# No images to scrape.
# Domains consistently defanged with [.].
# ISC separates domain from path/params in reports — strip_ioc_noise handles this.

class ISCSansScraper < BaseScraper
  SOURCE_NAME = 'SANS ISC'
  SOURCE_KEY  = 'isc_sans'
  BASE_URL    = 'https://isc.sans.edu'

  def initialize(years:, pages_back:, parallel:, output_file:, cache:, full_cache:,
                 cache_file:, dry_run:, browser_fetch: false, skip_ocr: false,
                 ocr_only: false, lookback_days: nil, **_opts)
    super(output_file: output_file, cache: cache, full_cache: full_cache,
          cache_file: cache_file, dry_run: dry_run, browser_fetch: browser_fetch,
          skip_ocr: skip_ocr)
    @years         = years
    @pages_back    = pages_back
    @lookback_days = lookback_days
    @parallel      = parallel
    @ocr_only      = ocr_only
  end

  def run
    puts "Mode         : #{@ocr_only ? 'OCR-only' : mode_label}"
    puts "Output file  : #{@output_file}"
    puts "Cache file   : #{@cache_file}"
    puts "OCR backend  : #{@skip_ocr ? 'skipped' : (ocr_backend || 'none')}"
    puts "(No images scraped for SANS ISC)"
    puts

    if @ocr_only
      puts "OCR-only: no images to rescan for SANS ISC."
    else
      articles = collect_article_urls
      puts "\nTotal articles to process: #{articles.size}\n\n"
      scrape_articles_parallel(articles) if articles.any?
    end

    unless @dry_run
      clean_blocklist
      write_to_blocklist
    end

    save_cache
    print_summary
  end

  private

  def mode_label
    last = most_recent_cached_date
    if @years
      "full scan (#{@years} year(s))"
    elsif last
      "incremental from #{last}"
    else
      "first run — full scan (#{DEFAULT_YEARS} year(s))"
    end
  end

  def collect_article_urls
    articles = []
    seen     = Set.new
    cutoff   = Date.today << ((@years || DEFAULT_YEARS) * 12)
    today    = Date.today

    puts "Collecting SANS ISC diary entries by year/month..."

    # Walk from today backward month by month until cutoff
    year  = today.year
    month = today.month

    loop do
      current = Date.new(year, month, 1)
      break if current < cutoff

      url  = "#{BASE_URL}/diaryarchive.html?year=#{year}&month=#{month}"
      puts "  #{year}-#{month.to_s.rjust(2, '0')}: #{url}"

      resp = fetch_with_retry(url)
      unless resp
        puts "  -> Failed"
        break
      end

      doc = Nokogiri::HTML(resp.body)
      doc.css('a[href*="/diary/"]').each do |link|
        href = link['href']
        href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
        next if seen.include?(href)
        next unless href.match?(/\/diary\//)
        seen.add(href)
        next if @cache['articles'][href]
        title = link.text.strip
        articles << { url: href, title: title, date_str: current.to_s, date: current }
      end

      # Step back one month
      month -= 1
      if month < 1
        month = 12
        year -= 1
      end
      sleep 0.3
    end

    articles
  end

  def scrape_article(article)
    url  = article[:url]
    resp = fetch_with_retry(url)
    unless resp
      @mutex.synchronize { puts "  [FAILED  ] #{url}" }
      return
    end

    doc  = Nokogiri::HTML(resp.body)
    title = article[:title] || doc.at_css('h1')&.text&.strip

    domains = Set.new
    ips     = Set.new
    content = article_content(doc)
    scan_for_iocs(content&.text.to_s, domains, ips)

    # ISC IoC sections
    ioc_text = extract_ioc_section(doc, headings: IOC_HEADINGS + ['domains seen', 'urls seen', 'iocs'])
    scan_for_iocs(ioc_text.to_s, domains, ips, plain_text: true)

    all_found = (domains.to_a + ips.to_a).sort.uniq

    entry = {
      'url'                  => url,
      'title'                => title,
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
      @pending[url] = { domains: all_found, title: title, date: article[:date_str] } if all_found.any?
    end
  end

  def article_content(doc)
    doc.at_css('.diarytext, .diary-text, article, main, .content') || doc.at_css('body')
  end
end
