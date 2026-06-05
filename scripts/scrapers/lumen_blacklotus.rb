# frozen_string_literal: true
# Lumen Black Lotus Labs scraper
#
# blog.lumen.com redirects to lumen.com/blog-and-news/en-us/home (AEM CMS, JS-rendered).
# The sitemap (sitemap-index.xml → en-us/sitemap.xml) does NOT include blog posts.
# The archive page (blog-and-news/en-us/black-lotus-labs) is JS-rendered — no static links.
#
# Working approach:
#   Fetch the static Black Lotus Labs landing page which embeds article links in HTML,
#   then extract all /blog/en-us/<slug> hrefs.
#
# Article URLs: https://www.lumen.com/blog/en-us/<slug>

LUMEN_BASE          = 'https://www.lumen.com'
LUMEN_LANDING_URL   = "#{LUMEN_BASE}/en-us/security/black-lotus-labs.html"
LUMEN_ARCHIVE_URL   = "#{LUMEN_BASE}/blog-and-news/en-us/black-lotus-labs"

# Matches /blog/en-us/<slug> — excludes hub/archive pages like /blog-and-news/en-us/black-lotus-labs
LUMEN_PATH_RE = %r{lumen\.com/blog/en-us/[a-z0-9][a-z0-9\-]+/?$}

class LumenBlackLotusLabsScraper < StandardPaginatedScraper
  SOURCE_NAME = 'Lumen Black Lotus Labs'
  SOURCE_KEY  = 'lumen_blacklotus'
  BASE_URL    = LUMEN_BASE

  private

  def collect_article_urls
    articles = []
    seen     = Set.new

    # Primary: landing page has hardcoded article links in static HTML
    [LUMEN_LANDING_URL, LUMEN_ARCHIVE_URL].each do |page_url|
      resp = fetch_with_retry(page_url)
      next unless resp&.success?

      doc = Nokogiri::HTML(resp.body)
      doc.css('a[href*="/blog/en-us/"]').each do |link|
        href = link['href'].to_s.strip
        next if href.empty?
        href = href.start_with?('http') ? href : "#{LUMEN_BASE}#{href}"
        next unless href.match?(LUMEN_PATH_RE)
        next unless seen.add?(href)
        next if cached?(href)

        title = link.text.strip
        articles << { url: href, title: title, date: nil, date_str: nil }
      end
    end

    puts "  -> #{articles.size} Black Lotus Labs articles found"
    articles
  end

  def listing_url(_page) = LUMEN_LANDING_URL
  def parse_listing(_doc) = []

  def extract_article_date(doc)
    meta = doc.at_css('meta[property="article:published_time"]') ||
           doc.at_css('meta[name="date"]')
    return Date.parse(meta['content']) if meta
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    # AEM pages sometimes embed date in JSON-LD
    ld = doc.at_css('script[type="application/ld+json"]')
    if ld
      data = JSON.parse(scrub(ld.text)) rescue {}
      pub = data['datePublished'] || data['dateCreated']
      return Date.parse(pub) if pub
    end
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.article-content, .blog-content, .rte, article, main') || doc.at_css('body')
  end
end
