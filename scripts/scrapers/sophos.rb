# frozen_string_literal: true
# Sophos Threat Research Blog scraper
# Pagination: https://www.sophos.com/en-us/blog?page=N
# IoC section: no fixed heading — threat indicator tables are scanned directly via scan_extra.

class SophosScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Sophos Threat Research'
  SOURCE_KEY  = 'sophos'
  BASE_URL    = 'https://www.sophos.com'

  private

  def listing_url(page)
    page == 1 ? "#{BASE_URL}/en-us/blog" : "#{BASE_URL}/en-us/blog?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('article, [class*="blog-card"], [class*="post-card"], [class*="article-card"]').each do |card|
      link = card.at_css('a[href*="/en-us/blog/"]') || card.at_css('h2 a, h3 a, h4 a')
      next unless link

      href = link['href'].to_s
      next if href.empty?
      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      next unless href.include?('/en-us/blog/')
      next if href.match?(%r{/en-us/blog/?\z})
      next if seen.include?(href)
      seen.add(href)

      title = link['title']&.strip || link.text.strip
      next if title.empty?

      date = parse_article_date(card)
      articles << { url: href, title: title, date_str: date&.to_s, date: date }
    end

    # Fallback: any blog-post-depth link found on the page
    if articles.empty?
      doc.css('a[href*="/en-us/blog/"]').each do |link|
        href = link['href'].to_s
        href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
        next unless href.match?(%r{/en-us/blog/[^/?#]+\z})
        next if seen.include?(href)
        seen.add(href)
        title = link['title']&.strip || link.text.strip
        next if title.empty? || title.length < 8
        articles << { url: href, title: title, date_str: nil, date: nil }
      end
    end

    articles
  end

  def parse_article_date(node)
    time_el = node.at_css('time[datetime]')
    return (Date.parse(time_el['datetime']) rescue nil) if time_el

    # Common prose formats: "May 5, 2026", "5 May 2026", "2026-05-05"
    text = node.text
    if text =~ /\b(\w{3,9}\s+\d{1,2},?\s+\d{4}|\d{1,2}\s+\w{3,9}\s+\d{4}|\d{4}-\d{2}-\d{2})\b/
      return (Date.parse(::Regexp.last_match(1)) rescue nil)
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

  # Scans tables whose column headers suggest threat-indicator content.
  # Uses plain_text mode so non-defanged IPs and domains are also captured.
  # Called automatically by StandardPaginatedScraper#scrape_article via scan_extra hook.
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

  def parallel_workers   = 3
  def batch_delay        = 1
  def listing_page_delay = 1
end
