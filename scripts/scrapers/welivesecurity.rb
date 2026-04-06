# frozen_string_literal: true
# ESET WeLiveSecurity scraper
# Pagination: https://www.welivesecurity.com/en/?page=N
# IoC section: "IoCs" + "Network" subsection (table of IPs and domains)
# Consistent [.] defanging. Images: web-assets.esetstatic.com

class WeLiveSecurityScraper < StandardPaginatedScraper
  SOURCE_NAME = 'ESET WeLiveSecurity'
  SOURCE_KEY  = 'welivesecurity'
  BASE_URL    = 'https://www.welivesecurity.com'

  private

  def listing_url(page)
    page == 1 ? "#{BASE_URL}/en/" : "#{BASE_URL}/en/?page=#{page}"
  end

  def parse_listing(doc)
    articles = []
    seen = Set.new

    # Cards are <a href="/en/cat/slug/" title="Article Title"> — no article/h3 wrapper.
    # Title lives in the `title` attribute; date is in the surrounding card text.
    doc.css('a[href][title]').each do |link|
      href = link['href'].to_s
      next unless href.match?(%r{/en/[^/?#]+/[^/?#]+})
      next if href.match?(%r{/en/(company|rss|legal|privacy|tag|author|search|page)/})
      next if href.include?('/feed')

      title = link['title'].strip
      next if title.empty?

      # Use parent node text to find the date — nav/footer links have none,
      # which naturally filters them out.
      date = parse_article_date(link.parent)
      next unless date

      href = href.start_with?('http') ? href : "#{BASE_URL}#{href}"
      next if seen.include?(href)
      seen.add(href)

      articles << { url: href, title: title, date_str: date.to_s, date: date }
    end
    articles
  end

  def parse_article_date(node)
    # Date appears in card text as "DD Mon YYYY", e.g. "19 Mar 2026"
    text = node.text
    if text =~ /\b(\d{1,2}\s+\w{3}\s+\d{4})\b/
      return Date.parse(::Regexp.last_match(1))
    end
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def parallel_workers   = 3
  def batch_delay        = 2
  def listing_page_delay = 2

  def ioc_headings
    IOC_HEADINGS + ['ioc', 'iocs', 'network', 'network indicators', 'appendix', 'malware samples']
  end
end
