# frozen_string_literal: true
# Sonatype Security Research blog scraper
# URL: https://www.sonatype.com/blog (note: blog.sonatype.com is defunct)
# Pagination: ?page=N (HubSpot CMS, 17+ pages)
# Category filter: ?category=all&type=all&page=N
# Supply-chain articles confirmed at paths like:
#   /blog/lazarus-groups-latest-brandjacking-campaign-on-npm

SONATYPE_BASE    = 'https://www.sonatype.com'
SONATYPE_BLOG    = "#{SONATYPE_BASE}/blog"

# Title keywords to avoid fetching every Sonatype blog post
SONATYPE_TITLE_KEYWORDS = %w[
  npm pypi pip rubygems package packages supply.chain typosquat
  malicious.package open.source nuget maven gradle crates dependency
  backdoor stealer brandjacking confusion attack
].freeze

class SonatypeScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Sonatype Security Research'
  SOURCE_KEY  = 'sonatype'
  BASE_URL    = SONATYPE_BASE

  private

  def listing_url(page)
    # HubSpot CMS uses ?page=N (0-indexed, but page 0 and page 1 both work)
    page == 1 ? SONATYPE_BLOG : "#{SONATYPE_BLOG}?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('article, .post, [class*="blog-post"], [class*="BlogCard"]').each do |art|
      link = art.at_css('h1 a, h2 a, h3 a, .entry-title a, [class*="title"] a')
      next unless link

      href = link['href'].to_s
      next if href.empty?
      href = href.start_with?('http') ? href : "#{SONATYPE_BASE}#{href}"
      next unless href.include?('sonatype.com/blog')
      next unless seen.add?(href)

      title = link.text.strip
      next unless SONATYPE_TITLE_KEYWORDS.any? { |kw| title.downcase.match?(kw) }

      date = parse_article_date(art)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end

    # Fallback
    if articles.empty?
      doc.css('a[href*="/blog/"]').each do |link|
        href = link['href'].to_s
        href = href.start_with?('http') ? href : "#{SONATYPE_BASE}#{href}"
        next unless href.match?(%r{sonatype\.com/blog/[a-z0-9\-]+/?$})
        next unless seen.add?(href)
        title = link.text.strip
        next unless SONATYPE_TITLE_KEYWORDS.any? { |kw| title.downcase.match?(kw) }
        articles << { url: href, title: title, date_str: nil, date: nil }
      end
    end

    articles
  end

  def parse_article_date(node)
    time_el = node.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    span = node.at_css('.entry-date, .post-date, .date, [class*="date"]')
    return Date.parse(span.text.strip) if span
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

  def parallel_workers = 3
  def batch_delay      = 1
  def max_pages        = 20
end
