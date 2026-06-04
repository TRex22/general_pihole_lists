# frozen_string_literal: true
# Snyk Security blog scraper
# Pagination: ?page=N (Next.js, 24 posts/page, 69+ pages, 1639+ total posts)
# URL confirmed: snyk.io/blog/?page=N

SNYK_BASE = 'https://snyk.io'

# Supply-chain / malicious-package article title keywords — filter at listing
# stage to avoid fetching 1639+ general security posts.
SNYK_TITLE_KEYWORDS = %w[
  npm pypi pip rubygems package packages supply.chain typosquat
  malicious.package open.source.package crates.io nuget maven
  dependency.confusion stealer backdoor trojan regreSSHion
  compromised.package registry attack
].freeze

class SnykScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Snyk Security Research'
  SOURCE_KEY  = 'snyk'
  BASE_URL    = SNYK_BASE

  private

  def listing_url(page)
    page == 1 ? "#{SNYK_BASE}/blog/" : "#{SNYK_BASE}/blog/?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('article, [class*="BlogCard"], [class*="blog-card"], [class*="PostCard"]').each do |art|
      link = art.at_css('h1 a, h2 a, h3 a, [class*="title"] a, a[href*="/blog/"]')
      next unless link

      href = link['href'].to_s
      next if href.empty?
      href = href.start_with?('http') ? href : "#{SNYK_BASE}#{href}"
      next unless href.match?(%r{snyk\.io/blog/[^/]+/?$})
      next unless seen.add?(href)

      title = link.text.strip
      # Filter for package-relevant articles at listing time
      next unless SNYK_TITLE_KEYWORDS.any? { |kw| title.downcase.match?(kw) }

      date = parse_article_date(art)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end

    # Fallback: broader link scan
    if articles.empty?
      doc.css('a[href*="/blog/"]').each do |link|
        href = link['href'].to_s
        href = href.start_with?('http') ? href : "#{SNYK_BASE}#{href}"
        next unless href.match?(%r{snyk\.io/blog/[a-z0-9\-]+/?$})
        next unless seen.add?(href)
        title = link.text.strip
        next unless SNYK_TITLE_KEYWORDS.any? { |kw| title.downcase.match?(kw) }
        articles << { url: href, title: title, date_str: nil, date: nil }
      end
    end

    articles
  end

  def parse_article_date(node)
    time_el = node.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    span = node.at_css('[class*="date"], [class*="Date"]')
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
    doc.at_css('.blog-content, .post-content, .entry-content, article, main') || doc.at_css('body')
  end

  def parallel_workers = 3
  def batch_delay      = 1
end
