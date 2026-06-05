# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with this repository.

## Project Overview

Pi-hole allowlist and blocklist collection with Ruby scripts for:
- Extracting domains from uBlock Origin filter lists
- Scraping security news sites for malicious domains (defanged IoCs)
- Building a malicious packages database (npm, PyPI, RubyGems, Cargo, NuGet, Go, Maven, etc.)

## Repository Structure

```
allowlists/         Domain allowlists by service (apple, aws, claude, google, etc.)
blocklists/         Domain blocklists
  malicious.txt     Scraped malicious domains (auto-updated)
  ublock/           Generated from uBlock Origin filter lists
  privacy-badger/   Generated from Privacy Badger lists
databases/          Generated databases (committed to repo)
  malicious_packages.json   Malicious package database (JSON)
  malicious_packages.csv    Malicious package database (CSV)
scripts/
  base_scraper.rb             Shared BaseScraper + StandardPaginatedScraper
  blocklist_project_filter.rb Shared domain skip constants + Blocklist Project API
  scrape_malicious_domains.rb Domain scraper CLI + scraper loader
  scrape_malicious_packages.rb Package scraper CLI + PackageBaseScraper + database writer
  extract_ublock_lists.rb     uBlock Origin list generator
  extract_privacy_badger_lists.rb Privacy Badger list generator
  extract_pihole_logs.rb      Pi-hole query log analysis
  ai_review_blocklists.rb     DSPy-powered AI allowlist/blocklist review
  update_all_lists.sh         Runs all four update scripts in sequence
  ocr_macos.swift             macOS Vision OCR helper (compiled on first run)
  scrapers/                   Domain scraper plugins (one per source)
  package_scrapers/           Package scraper plugins (one per source)
```

## Ruby Version

Ruby 4.0.0 (see `.ruby-version`). Run `bundle install` to install gems.

## Commands

### Run All Updates

```bash
bash scripts/update_all_lists.sh
```

### Generate uBlock Origin Blocklists

```bash
ruby scripts/extract_ublock_lists.rb                        # all default filter lists
ruby scripts/extract_ublock_lists.rb --available            # show available lists
ruby scripts/extract_ublock_lists.rb --lists easylist,easyprivacy,peter-lowe
ruby scripts/extract_ublock_lists.rb --output-dir /path/to/output
```

Output: `blocklists/ublock/` — `blocklist.txt`, `hosts.txt`, `allowlist.txt`, `sources.txt`

### Scrape Malicious Domains

```bash
ruby scripts/scrape_malicious_domains.rb                    # incremental (new since last run)
ruby scripts/scrape_malicious_domains.rb --years 2          # full scan 2 years back
ruby scripts/scrape_malicious_domains.rb --lookback-days 7  # 7-day overlap window
ruby scripts/scrape_malicious_domains.rb --parallel 30      # thread count
ruby scripts/scrape_malicious_domains.rb --sources bleepingcomputer,talos
ruby scripts/scrape_malicious_domains.rb --dry-run          # scrape without writing
ruby scripts/scrape_malicious_domains.rb --status           # show cache stats table
ruby scripts/scrape_malicious_domains.rb --skip-ocr         # skip image OCR
ruby scripts/scrape_malicious_domains.rb --help
```

Output: `blocklists/malicious.txt`
Cache: `scripts/malicious_domains_cache.json` (git-ignored)

Domain sources: `thehackernews`, `bleepingcomputer`, `krebsonsecurity`, `isc_sans`,
`talos`, `unit42`, `securelist`, `malwarebytes`, `welivesecurity`, `proofpoint`,
`microsoft_security`, `google_threat_intel`, `anyrun`, `sophos`,
`checkpoint_research`, `volexity`, `sentinelone`, `elastic_security`,
`zscaler_threatlabz`, `symantec_threatintel`, `lumen_blacklotus`, `red_canary`,
`fortiguard`, `trendmicro`, `crowdstrike`, `huntress`

Note: `fortiguard`, `trendmicro`, `crowdstrike`, and `huntress` block datacenter IP
ranges. Run with `--browser-fetch` or from a residential/office network if they
return 0 articles.

### Scrape Malicious Packages Database

```bash
ruby scripts/scrape_malicious_packages.rb                   # incremental
ruby scripts/scrape_malicious_packages.rb --years 2         # full scan
ruby scripts/scrape_malicious_packages.rb --lookback-days 7
ruby scripts/scrape_malicious_packages.rb --parallel 5
ruby scripts/scrape_malicious_packages.rb --sources ossf,socket_dev
ruby scripts/scrape_malicious_packages.rb --dry-run
ruby scripts/scrape_malicious_packages.rb --status          # show cache stats
ruby scripts/scrape_malicious_packages.rb --help
```

Output: `databases/malicious_packages.json` and `databases/malicious_packages.csv`
Cache: `scripts/malicious_packages_cache.json` (git-ignored)

Package sources:
- **Structured/dedicated** (high confidence): `ossf` (OSSF malicious-packages GitHub repo),
  `socket_dev` (Socket.dev blog), `checkmarx` (WP REST API, category supply-chain-security),
  `jfrog` (security-research tag), `snyk`, `sonatype`, `aqua_security`
- **Generalist security blogs** (medium confidence): `thehackernews`, `bleepingcomputer`,
  `talos`, `unit42`, `securelist`, `microsoft_security`, `google_threat_intel`

### OSSF source notes

The `ossf` scraper uses the GitHub Git Trees API (not Contents API) to avoid rate limiting.
Set `GITHUB_TOKEN` env var to use authenticated requests (5000 req/hr vs 60 req/hr).
Structure: `osv/{status}/{ecosystem}/{package}` where status ∈ {malicious, unmergable, withdrawn}.

## Database Output Format

### JSON (`databases/malicious_packages.json`)
```json
{
  "generated_at": "2026-01-01T00:00:00Z",
  "total": 1234,
  "packages": [
    {
      "name": "malicious-pkg",
      "type": "npm",
      "sources": [
        { "url": "https://...", "title": "Article title", "date": "2024-01-01" }
      ],
      "first_seen": "2024-01-01",
      "last_seen": "2024-01-02"
    }
  ]
}
```

### CSV (`databases/malicious_packages.csv`)
Columns: `name, type, sources (JSON array), first_seen, last_seen`

## List File Format

All list files use Pi-hole compatible format:
- One domain per line
- Comments start with `#`
- No wildcards (Pi-hole regex lists require separate handling)

## Cross-File Duplication Policy

Duplicating a domain across multiple allowlist files is acceptable and intentional.
Pi-hole deduplicates allowlist entries at load time. When duplicating, add a comment
noting the cross-reference (e.g. `# also in general.txt`).

## Regex and Plain Domain Policy

When a regex pattern is added to `regex_allowlist.txt`, do **NOT** remove the
corresponding explicit domain entries from the plain allowlist files. Both must coexist:
- Plain entries work on Pi-hole instances without regex allowlist support
- Plain entries document intent and are self-describing
- Plain entries match faster and survive regex file misconfiguration

## Shared Infrastructure

`scripts/base_scraper.rb` is required by both scraper scripts. It provides:
- `BaseScraper` — HTTP (`fetch_with_retry`, rate limiting, browser fetch), OCR pipeline,
  domain validation, blocklist I/O, cache I/O
- `StandardPaginatedScraper < BaseScraper` — pagination loop for domain scrapers
- `load_full_cache` — JSON cache helper with old-format migration

`scripts/blocklist_project_filter.rb` provides domain-skip constants (`SKIP_DOMAINS`,
`EXACT_SKIP_DOMAINS`, `SKIP_IPS`, `FILE_EXTENSION_TLDS`) and `skip_domain_static?`.

## Adding a New Package Scraper

1. Create `scripts/package_scrapers/mysite.rb`
2. Inherit from `PackageStandardPaginatedScraper` (for paginated blogs) or
   `PackageBaseScraper` (for APIs/structured sources)
3. Define `SOURCE_NAME`, `SOURCE_KEY`, `BASE_URL`
4. Implement `listing_url(page)` and `parse_listing(doc)` (or override `collect_article_urls`)
5. Add to `ALL_PACKAGE_SCRAPERS` hash in `scrape_malicious_packages.rb`
6. Add `require_relative 'package_scrapers/mysite'` in `scrape_malicious_packages.rb`

Before implementing, **research the site's actual pagination API**:
- Check for WordPress REST API (`/wp-json/wp/v2/posts`) — preferred over HTML scraping
- Check for Algolia, Elasticsearch, or other search API hints in page source
- Use `WebFetch` to browse the live site and inspect pagination controls
- Note whether it uses `?page=N`, `/page/N/`, or AJAX "load more"

## Available Filter List Sources (uBlock)

`ublock-filters`, `ublock-badware`, `ublock-privacy`, `ublock-unbreak`, `easylist`,
`easyprivacy`, `peter-lowe`, `urlhaus-malware`, `adguard-dns`, `steven-black-hosts`,
`energized-basic`, `oisd-basic`
