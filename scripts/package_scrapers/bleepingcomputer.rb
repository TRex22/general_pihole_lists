# frozen_string_literal: true
# BleepingComputer package scraper — /news/security/ listing
# Pagination: /news/security/ (page 1), /news/security/page/N/ (N≥2)

PKG_BC_BASE = 'https://www.bleepingcomputer.com'

# Keyword filter applied to article titles on the listing page to avoid
# fetching every security article — BC is high-volume general security news.
PKG_BC_TITLE_KEYWORDS = %w[
  npm pypi pip rubygems package packages supply.chain typosquat
  malicious.package open.source.package nuget crates.io maven gradle
  dependency.confusion stealer backdoor trojan
].freeze

class PackageBleepingComputerScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'BleepingComputer (packages)'
  SOURCE_KEY  = 'bleepingcomputer'
  BASE_URL    = PKG_BC_BASE

  private

  def listing_url(page)
    page == 1 ? "#{BASE_URL}/news/security/" : "#{BASE_URL}/news/security/page/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('h4').each do |h4|
      link = h4.at_css('a[href]')
      next unless link

      href = link['href'].to_s
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"

      begin
        uri = URI.parse(href)
        next unless uri.host&.end_with?('bleepingcomputer.com') && uri.path.start_with?('/news/')
      rescue URI::Error
        next
      end

      next unless seen.add?(href)

      title = link.text.strip
      # Filter for package-related articles at listing stage
      next unless PKG_BC_TITLE_KEYWORDS.any? { |kw| title.downcase.match?(kw) }

      date = parse_article_date(h4)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end

    articles
  end

  def parse_article_date(node)
    container = node.parent
    date_li   = container&.at_css('li.bc_news_date')
    return Date.parse(date_li.text.strip) if date_li

    time_el = container&.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def extract_article_date(doc)
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.article-body, .post-body, article, main') || doc.at_css('body')
  end

  def parallel_workers = 3
  def batch_delay      = 2
end
