# frozen_string_literal: true
# CrowdStrike Blog scraper
#
# crowdstrike.com blocks cloud/datacenter IPs (ECONNREFUSED).
# Run with --browser-fetch if you get connection errors.
#
# Discovery order:
#   1. RSS  at /en-us/blog/feed/          — incremental mode only
#   2. sitemap_index.xml → post-sitemap.xml + post-sitemap2.xml (2019–present)
#   3. blog/sitemap_index.xml             — flat sitemap, 2012–2019 content
#
# NOTE: ?page=N pagination does NOT work — the site uses JS infinite scroll
# and returns the same ~60 articles regardless of the page parameter.
#
# Article URLs (both formats exist):
#   https://www.crowdstrike.com/en-us/blog/<slug>/   (2019–present)
#   https://www.crowdstrike.com/blog/<slug>/         (2012–2019 archive)

CROWDSTRIKE_BASE             = 'https://www.crowdstrike.com'
CROWDSTRIKE_SITEMAP_IDX_URL  = "#{CROWDSTRIKE_BASE}/sitemap_index.xml"
CROWDSTRIKE_BLOG_SITEMAP_URL = "#{CROWDSTRIKE_BASE}/blog/sitemap_index.xml"
CROWDSTRIKE_RSS_URL          = "#{CROWDSTRIKE_BASE}/en-us/blog/feed/"

# Matches both old (/blog/) and new (/en-us/blog/) URL formats.
# Slug must start with alphanumeric and be at least 5 chars to skip
# navigation stubs like /blog/videos/ or /blog/categories-overview/
CROWDSTRIKE_PATH_RE = %r{crowdstrike\.com/(?:en-us/)?blog/[a-z0-9][a-z0-9\-]{4,}/?$}

# Short slugs that are navigation/index pages, not articles
CROWDSTRIKE_NAV_SLUGS = %w[
  recent-articles featured-articles categories-overview videos press-releases
  threat-intelligence adversary-intelligence adversary-intel
].freeze

class CrowdStrikeScraper < StandardPaginatedScraper
  SOURCE_NAME = 'CrowdStrike Blog'
  SOURCE_KEY  = 'crowdstrike'
  BASE_URL    = CROWDSTRIKE_BASE

  private

  def collect_article_urls
    incremental = @years.nil? && !most_recent_cached_date.nil?
    return (collect_via_rss(CROWDSTRIKE_RSS_URL) || collect_from_sitemaps) if incremental

    collect_from_sitemaps
  end

  def collect_from_sitemaps
    # sitemap_index.xml → post-sitemap.xml + post-sitemap2.xml (recent, Yoast SEO)
    recent  = collect_via_sitemap(CROWDSTRIKE_SITEMAP_IDX_URL,  path_re: CROWDSTRIKE_PATH_RE) || []

    # blog/sitemap_index.xml is a flat sitemap of the older /blog/ URL format
    archive = collect_via_sitemap(CROWDSTRIKE_BLOG_SITEMAP_URL, path_re: CROWDSTRIKE_PATH_RE) || []

    all = (recent + archive).uniq { |a| a[:url] }
    before = all.size
    all.reject! { |a| nav_slug?(a[:url]) }
    skipped = before - all.size
    puts "  -> #{all.size} article URLs (skipped #{skipped} navigation pages)" if skipped > 0
    all
  end

  def nav_slug?(url)
    slug = url.split('/').reject(&:empty?).last.to_s.chomp('/')
    CROWDSTRIKE_NAV_SLUGS.include?(slug)
  end

  # Stubs required by StandardPaginatedScraper interface (not called — no HTML pagination)
  def listing_url(_page) = "#{CROWDSTRIKE_BASE}/en-us/blog/"
  def parse_listing(_doc) = []

  def extract_article_date(doc)
    meta = doc.at_css('meta[property="article:published_time"]') ||
           doc.at_css('meta[name="date"]')
    return Date.parse(meta['content']) if meta
    time_el = doc.at_css('time[datetime]')
    return Date.parse(time_el['datetime']) if time_el
    ld = doc.at_css('script[type="application/ld+json"]')
    if ld
      data = JSON.parse(scrub(ld.text)) rescue {}
      pub = data['datePublished']
      return Date.parse(pub) if pub
    end
    nil
  rescue ArgumentError, TypeError
    nil
  end

  def article_content(doc)
    doc.at_css('.blog-post__body, .entry-content, article, main') || doc.at_css('body')
  end
end
