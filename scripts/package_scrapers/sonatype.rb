# frozen_string_literal: true
# Sonatype Security Research blog scraper
# URL: https://www.sonatype.com/blog (note: blog.sonatype.com is defunct)
# Pagination: ?category=all&type=all&page=N (HubSpot CMS, 0-indexed, ~18 pages)
# Confirmed: page=1 returns "Shai-Hulud npm" and "Lazarus/npm" articles
# Article links are <h3> headings; wrapper class unknown — use URL-pattern scan.

SONATYPE_BASE = 'https://www.sonatype.com'
SONATYPE_BLOG = "#{SONATYPE_BASE}/blog"

SONATYPE_TITLE_KEYWORDS = %w[
  npm pypi pip rubygems package packages supply.chain typosquat
  malicious.package open.source nuget maven gradle crates dependency
  backdoor backdoored stealer brandjacking confusion attack malware
  lazarus shai-hulud poisoning
].freeze

class SonatypeScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Sonatype Security Research'
  SOURCE_KEY  = 'sonatype'
  BASE_URL    = SONATYPE_BASE

  private

  # HubSpot CMS — 0-indexed pages, full params required.
  # collect_article_urls passes page=1,2,3… so subtract 1 for the query param.
  def listing_url(page)
    page == 1 ? SONATYPE_BLOG : "#{SONATYPE_BLOG}?category=all&type=all&page=#{page - 1}"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    # Try heading-link pattern (articles use <h3><a href>...)
    doc.css('h3 a[href*="/blog/"], h2 a[href*="/blog/"]').each do |link|
      href = link['href'].to_s
      next if href.empty?
      href = href.start_with?('http') ? href : "#{SONATYPE_BASE}#{href}"
      next unless href.match?(%r{sonatype\.com/blog/[a-z0-9\-]+/?$})
      next unless seen.add?(href)

      title = link.text.strip
      next unless SONATYPE_TITLE_KEYWORDS.any? { |kw| title.downcase.match?(kw) }

      date = extract_nearby_date(link)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end

    # Fallback: broader anchor scan
    if articles.empty?
      doc.css('a[href*="/blog/"]').each do |link|
        href = link['href'].to_s
        href = href.start_with?('http') ? href : "#{SONATYPE_BASE}#{href}"
        next unless href.match?(%r{sonatype\.com/blog/[a-z0-9][a-z0-9\-]+/?$})
        next if href.end_with?('/blog/', '/blog')
        next unless seen.add?(href)

        title = link.text.strip
        next if title.empty? || title.length < 10
        next unless SONATYPE_TITLE_KEYWORDS.any? { |kw| title.downcase.match?(kw) }

        articles << { url: href, title: title, date_str: nil, date: nil }
      end
    end

    articles
  end

  def extract_nearby_date(link)
    el = link
    3.times do
      el = el.parent
      break unless el
      time_el = el.at_css('time[datetime]')
      return Date.parse(time_el['datetime']) if time_el
      span = el.at_css('.date, [class*="date"]')
      return Date.parse(span.text.strip) if span
    end
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def extract_article_date(doc)
    meta = doc.at_css('meta[property="article:published_time"]')
    return Date.parse(meta['content']) if meta
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.entry-content, .post-content, article, main') || doc.at_css('body')
  end

  def max_pages = 20
  def parallel_workers = 3
  def batch_delay = 1
end
