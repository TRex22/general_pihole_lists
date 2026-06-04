# frozen_string_literal: true
# Sonatype Security Research blog scraper
# https://blog.sonatype.com
# Specialises in Maven, npm, PyPI, and NuGet supply chain attacks.

class SonatypeScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Sonatype Security Research'
  SOURCE_KEY  = 'sonatype'
  BASE_URL    = 'https://blog.sonatype.com'

  private

  def listing_url(page)
    # Sonatype uses standard WordPress pagination
    page == 1 ? BASE_URL : "#{BASE_URL}/page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('article, .post, .entry').each do |art|
      link = art.at_css('h1 a, h2 a, h3 a, .entry-title a')
      next unless link

      href = link['href'].to_s
      next if href.empty?
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      next unless seen.add?(href)

      title = link.text.strip
      date  = parse_article_date(art)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
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
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    meta = doc.at_css('meta[property="article:published_time"]')
    return Date.parse(meta['content']) if meta
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.entry-content, article, .post-content, main') || doc.at_css('body')
  end

  def parallel_workers = 3
  def batch_delay      = 1
end
