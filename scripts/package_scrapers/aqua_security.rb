# frozen_string_literal: true
# Aqua Security (Team Nautilus) blog scraper
# WordPress site: /blog/page/N/ pagination (confirmed)
# /blog/category/supply-chain-security/ returns 404 — scrape main blog instead.
# Card selectors unknown; use URL-pattern link scan as reliable fallback.

AQUA_BASE = 'https://www.aquasec.com'

AQUA_TITLE_KEYWORDS = %w[
  npm pypi pip rubygems package packages supply.chain typosquat
  malicious.package nuget crates cargo maven dependency
  backdoor stealer trojan attack open.source
].freeze

class AquaSecurityScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Aqua Security (Team Nautilus)'
  SOURCE_KEY  = 'aqua_security'
  BASE_URL    = AQUA_BASE

  private

  def listing_url(page)
    page == 1 ? "#{AQUA_BASE}/blog/" : "#{AQUA_BASE}/blog/page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    # Try WordPress article containers first
    doc.css('article, .post, .blog-post, [class*="post-card"], [class*="article-card"]').each do |art|
      link = art.at_css('h1 a, h2 a, h3 a, h4 a, .entry-title a')
      next unless link

      href = link['href'].to_s
      next if href.empty?
      href = href.start_with?('http') ? href : "#{AQUA_BASE}#{href}"
      next unless href.include?('aquasec.com/blog/')
      next unless seen.add?(href)

      title = link.text.strip
      next unless AQUA_TITLE_KEYWORDS.any? { |kw| title.downcase.match?(kw) }

      date = parse_article_date(art)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end

    # Fallback: URL-pattern scan (catches any card structure)
    if articles.empty?
      doc.css('a[href*="aquasec.com/blog/"]').each do |link|
        href = link['href'].to_s
        next if href.end_with?('/blog/', '/blog')
        next unless href.match?(%r{aquasec\.com/blog/[a-z0-9\-]+/?$})
        next unless seen.add?(href)

        title = link.text.strip
        next if title.empty?
        next unless AQUA_TITLE_KEYWORDS.any? { |kw| title.downcase.match?(kw) }

        articles << { url: href, title: title, date_str: nil, date: nil }
      end
    end

    articles
  end

  def parse_article_date(node)
    time_el = node.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    span = node.at_css('.entry-date, .post-date, .date')
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

  def max_pages = 20
end
