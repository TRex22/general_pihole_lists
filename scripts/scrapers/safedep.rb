# frozen_string_literal: true
# SafeDep blog scraper (malicious package / supply-chain research)
#
# safedep.io is an Astro site. Posts live at the site root (https://safedep.io/<slug>),
# NOT under /blog/, so the sitemap (~3000 URLs incl. per-package pages) can't be filtered
# by path. The RSS feed at /rss.xml lists every post (~150, back to 2024) and is the
# primary discovery path. Fallback: HTML listing /blog/ then /blog/N/ (trailing slash
# required, /blog/N 308-redirects).
#
# Article URLs: https://safedep.io/<slug>

SAFEDEP_BASE    = 'https://safedep.io'
SAFEDEP_RSS_URL = "#{SAFEDEP_BASE}/rss.xml"

# Top-level site pages that share the /<slug> shape but aren't blog posts.
SAFEDEP_NON_POSTS = %w[
  about agent ai-agent-runtime-security blog contact endpoint-protection faq
  how-safedep-works mcp oss pricing privacy shadow-ai terms threat-intel ti rss
].freeze

class SafeDepScraper < StandardPaginatedScraper
  SOURCE_NAME = 'SafeDep'
  SOURCE_KEY  = 'safedep'
  BASE_URL    = SAFEDEP_BASE

  private

  def collect_article_urls
    rss = collect_via_rss(SAFEDEP_RSS_URL)
    return rss if rss&.any?

    warn '  RSS returned nothing — falling back to HTML listing.'
    super
  end

  def listing_url(page)
    page == 1 ? "#{SAFEDEP_BASE}/blog/" : "#{SAFEDEP_BASE}/blog/#{page}/"
  end

  def parse_listing(doc)
    articles = []
    seen     = Set.new

    doc.css('a[href^="/"]').each do |link|
      slug = link['href'].to_s.strip[%r{\A/([a-z0-9][a-z0-9\-]+)/?\z}, 1]
      next if slug.nil? || SAFEDEP_NON_POSTS.include?(slug)
      href = "#{SAFEDEP_BASE}/#{slug}"
      next unless seen.add?(href)
      articles << { url: href, title: link.text.strip, date: nil, date_str: nil }
    end

    articles
  end

  def extract_article_date(doc)
    meta = doc.at_css('meta[property="article:published_time"]')
    return Date.parse(meta['content']) if meta
    ld = doc.at_css('script[type="application/ld+json"]')
    if ld
      data = JSON.parse(ld.text) rescue {}
      pub = data['datePublished']
      return Date.parse(pub) if pub
    end
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.blog-prose, .prose, article') || doc.at_css('main') || doc.at_css('body')
  end

  def max_pages = 20
end
