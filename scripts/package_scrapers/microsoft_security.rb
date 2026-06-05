# frozen_string_literal: true
# Microsoft Security Blog package scraper
# Pagination: ?paged=N (confirmed from "Load More" button href)
# Article cards are plain <div> wrappers — no article/.post class names.
# Use URL-pattern link scan rather than card container selectors.
# Dates: <span> with "Month Day" text, full date from article meta tag.

PKG_MSFT_BASE    = 'https://www.microsoft.com'
PKG_MSFT_LISTING = "#{PKG_MSFT_BASE}/en-us/security/blog/topic/threat-intelligence"

class PackageMicrosoftSecurityScraper < PackageStandardPaginatedScraper
  SOURCE_NAME = 'Microsoft Security Blog (packages)'
  SOURCE_KEY  = 'microsoft_security'
  BASE_URL    = PKG_MSFT_BASE

  private

  def listing_url(page)
    # ?sort-by interferes with ?paged — use just ?paged=N
    page == 1 ? "#{PKG_MSFT_LISTING}/" : "#{PKG_MSFT_LISTING}/?paged=#{page}"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    # Article cards are plain <div> containers with no class — match by URL pattern.
    # Year appears in the Microsoft blog URL: /security/blog/YYYY/MM/DD/slug
    doc.css('a[href*="/security/blog/20"]').each do |link|
      href = link['href'].to_s
      next if href.empty?
      href = href.start_with?('http') ? href : "#{PKG_MSFT_BASE}#{href}"
      next unless href.match?(%r{microsoft\.com/en-us/security/blog/20\d\d/\d\d/\d\d/})
      next unless seen.add?(href)

      # Title is in the nearest heading ancestor/sibling or link text
      title = extract_link_title(link)
      date  = extract_date_from_card(link)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end

    articles
  end

  def extract_link_title(link)
    # Title link wraps the heading text, or heading is a nearby sibling
    heading = link.at_css('h1, h2, h3, h4')
    return heading.text.strip if heading

    text = link.text.strip
    text.length > 5 ? text : nil
  end

  def extract_date_from_card(link)
    # Walk up to find a container that might have a date span
    el = link
    3.times do
      el = el.parent
      break unless el
      # "Month Day" span next to a "min read" span
      el.css('span, time').each do |span|
        text = span.text.strip
        return Date.parse("#{text} #{Date.today.year}") if text.match?(/\A[A-Z][a-z]+ \d{1,2}\z/)
        return Date.parse(span['datetime']) if span.name == 'time' && span['datetime']
      end
    end
    nil
  rescue ArgumentError
    nil
  end

  def extract_article_date(doc)
    meta = doc.at_css('meta[property="article:published_time"]') ||
           doc.at_css('meta[name="date"]') ||
           doc.at_css('meta[name="publish_date"]')
    return Date.parse(meta['content']) if meta

    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.entry-content, article, .post-content, main') || doc.at_css('body')
  end

  def max_pages = 20
end
