# frozen_string_literal: true
# JFrog Security Research blog scraper
#
# Discovery: post-sitemap.xml (all blog post URLs + lastmod dates).
# Archive pagination is client-side JavaScript and cannot be scraped with plain
# HTTP — the tag listing page always returns page 1 content regardless of query
# params (?pagenum=N, ?paged=N). The sitemap gives full URL coverage without
# JavaScript and is the authoritative source for blog post URLs.
#
# URL filter: only fetch articles whose slug suggests security/package content,
# avoiding the 1000+ general blog posts about Artifactory and DevOps.

JFROG_BASE         = 'https://jfrog.com'
JFROG_SITEMAP_URL  = "#{JFROG_BASE}/post-sitemap.xml"

JFROG_SLUG_KEYWORDS = %w[
  malware malicious supply-chain package npm pypi python ruby cargo nuget maven
  vulnerability cve attack backdoor trojan stealer security-research
  typosquat dependency threat shai-hulud picklescan obfuscat
].freeze

class JFrogScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'JFrog Security Research'
  SOURCE_KEY  = 'jfrog'
  BASE_URL    = JFROG_BASE

  private

  # Override: enumerate from sitemap, no pagination needed.
  def collect_article_urls
    cutoff      = Date.today << ((@years || PKG_DEFAULT_YEARS) * 12)
    last_date   = most_recent_cached_date
    incremental = @years.nil? && !last_date.nil?

    puts "  Fetching JFrog post sitemap..."
    resp = fetch_with_retry(JFROG_SITEMAP_URL)
    unless resp
      warn '  -> Sitemap unreachable — skipping JFrog.'
      return []
    end

    xml      = Nokogiri::XML(resp.body)
    all_urls = xml.css('url').filter_map do |node|
      loc     = node.at_css('loc')&.text&.strip
      lastmod = node.at_css('lastmod')&.text&.strip
      next unless loc&.match?(%r{jfrog\.com/blog/[a-z0-9]})
      date = lastmod ? (Date.parse(lastmod) rescue nil) : nil
      { url: loc, date: date }
    end

    puts "  -> #{all_urls.size} blog post URLs in sitemap"

    articles = all_urls.filter_map do |entry|
      url  = entry[:url]
      date = entry[:date]

      next if date && date < cutoff
      next if @cache['articles'][url]

      slug = url.split('/').last(2).join('/')
      next unless JFROG_SLUG_KEYWORDS.any? { |kw| slug.include?(kw) }

      { url: url, title: nil, date_str: date&.to_s, date: date }
    end

    puts "  -> #{articles.size} security-relevant uncached articles"

    if incremental && last_date
      lookback = @lookback_days&.positive? ? last_date - @lookback_days : last_date
      articles.select! { |a| a[:date].nil? || a[:date] >= lookback }
      puts "  -> #{articles.size} after incremental date filter"
    end

    articles
  end

  def extract_article_date(doc)
    meta = doc.at_css('meta[property="article:published_time"]')
    return Date.parse(meta['content']) if meta

    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el

    # Plain text date in card/header: "March 05, 2026"
    doc.css('p, span').each do |el|
      text = el.text.strip
      return Date.parse(text) if text.match?(/\A[A-Z][a-z]+ \d{1,2},\s*\d{4}\z/)
    end
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.entry-content, .post-content, article, main') || doc.at_css('body')
  end

  # Unused — collect_article_urls overrides the pagination loop entirely
  def listing_url(page) = "#{JFROG_BASE}/blog/tag/security-research/"
  def parse_listing(_doc) = []
end
