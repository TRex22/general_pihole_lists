# general_pihole_lists

My own Pi-hole allowlists and blocklists, with automation scripts for generating and updating them.

---

## Repository Structure

```
allowlists/           Curated domain allowlists by service
blocklists/
  malicious.txt       Scraped malicious domains (auto-updated daily)
  ublock/             Generated from uBlock Origin filter lists
  privacy-badger/     Generated from EFF Privacy Badger seed data
malicious_package_database/
  malicious_packages.json   Known malicious package database (JSON)
  malicious_packages.csv    Known malicious package database (CSV)
scripts/              Automation scripts (see below)
```

---

## Scripts

### `scrape_malicious_domains.rb`

Scrapes security news blogs for defanged IoC domains (e.g. `evil[.]com`) and appends them to `blocklists/malicious.txt`. Uses incremental caching so each run only processes new articles. Each source is timed and a total elapsed time is printed at the end.

```sh
# Incremental run — only new articles since last cached date (recommended)
ruby scripts/scrape_malicious_domains.rb

# Go back 14 days before the last cached article
ruby scripts/scrape_malicious_domains.rb --lookback-days 14

# Full scan for 3 years + re-OCR all cached images
ruby scripts/scrape_malicious_domains.rb --years 3 --rescan-images

# Specific sources only
ruby scripts/scrape_malicious_domains.rb --sources bleepingcomputer,talos

# Skip specific sources (e.g. those that block your IP range)
ruby scripts/scrape_malicious_domains.rb --skip-sources trendmicro,sophos

# Control parallel threads and HTTP read timeout
ruby scripts/scrape_malicious_domains.rb --parallel 10 --read-timeout 10

# Dry run (scrape and cache but don't write to blocklist)
ruby scripts/scrape_malicious_domains.rb --dry-run

# Show cache status table for all sources
ruby scripts/scrape_malicious_domains.rb --status

# All options
ruby scripts/scrape_malicious_domains.rb --help
```

**Sources:** `thehackernews`, `bleepingcomputer`, `krebsonsecurity`, `isc_sans`, `talos`, `unit42`, `securelist`, `malwarebytes`, `welivesecurity`, `proofpoint`, `microsoft_security`, `google_threat_intel`, `anyrun`, `sophos`, `checkpoint_research`, `volexity`, `sentinelone`, `elastic_security`, `zscaler_threatlabz`, `symantec_threatintel`, `lumen_blacklotus`, `red_canary`, `fortiguard`, `trendmicro`, `crowdstrike`, `huntress`

> **Note:** `fortiguard`, `trendmicro`, `sophos`, `crowdstrike`, and `huntress` block datacenter IP ranges. The GitHub Actions workflow skips `trendmicro` and `sophos` by default (`--skip-sources trendmicro,sophos`). Run with `--browser-fetch` or from a residential/office network if these return 0 articles.

**Cache file:** `scripts/malicious_domains_cache.json` (git-ignored)

---

### `scrape_malicious_packages.rb`

Builds a database of known malicious packages (npm, PyPI, RubyGems, Cargo, NuGet, Go, Maven, etc.) from structured feeds and security blog scraping. Output is written to `malicious_package_database/` and committed to the repository. Each source is timed and a total elapsed time is printed at the end.

```sh
# Incremental run — only new content since last cached date (recommended)
ruby scripts/scrape_malicious_packages.rb

# Go back 7 days before the last cached article
ruby scripts/scrape_malicious_packages.rb --lookback-days 7

# Full scan for 2 years
ruby scripts/scrape_malicious_packages.rb --years 2

# Specific sources only
ruby scripts/scrape_malicious_packages.rb --sources ossf,socket_dev

# Skip specific sources (e.g. those that block your IP range)
ruby scripts/scrape_malicious_packages.rb --skip-sources socket_dev

# Control parallel threads and HTTP read timeout
ruby scripts/scrape_malicious_packages.rb --parallel 5 --read-timeout 10

# Dry run (scrape and cache but don't write database files)
ruby scripts/scrape_malicious_packages.rb --dry-run

# Show cache status table for all sources
ruby scripts/scrape_malicious_packages.rb --status

# All options
ruby scripts/scrape_malicious_packages.rb --help
```

**Structured sources** (high confidence):
| Source | Method |
|--------|--------|
| `ossf` | [OSSF malicious-packages](https://github.com/ossf/malicious-packages) GitHub Git Trees API |
| `socket_dev` | [Socket.dev](https://socket.dev/blog) blog (`?page=N`) |
| `checkmarx` | [Checkmarx](https://checkmarx.com/blog/) WordPress REST API |
| `jfrog` | [JFrog Security Research](https://jfrog.com/blog/tag/security-research/) sitemap |
| `snyk` | [Snyk Security](https://snyk.io/blog/) blog (`?page=N`) |
| `sonatype` | [Sonatype](https://www.sonatype.com/blog) blog (`?category=all&type=all&page=N`) |
| `aqua_security` | [Aqua Security](https://www.aquasec.com/blog/) WordPress (`/page/N/`) |

**Generalist security blogs** (medium confidence, filtered by title keywords):
`thehackernews`, `bleepingcomputer`, `talos`, `unit42`, `securelist`, `microsoft_security`, `google_threat_intel`

> **Note:** `socket_dev` blocks datacenter IP ranges. The GitHub Actions workflow skips it by default (`--skip-sources socket_dev`).

**Cache file:** `scripts/malicious_packages_cache.json` (git-ignored)

#### Database output format

**JSON** (`malicious_package_database/malicious_packages.json`):
```json
{
  "generated_at": "2026-01-01T00:00:00Z",
  "total": 51000,
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

**CSV** (`malicious_package_database/malicious_packages.csv`) — columns: `name, type, sources (JSON array), first_seen, last_seen`

---

### `extract_ublock_lists.rb`

Downloads uBlock Origin filter lists and generates Pi-hole-compatible blocklists.

```sh
ruby scripts/extract_ublock_lists.rb                               # all default lists
ruby scripts/extract_ublock_lists.rb --available                   # show available sources
ruby scripts/extract_ublock_lists.rb --lists easylist,easyprivacy,peter-lowe
ruby scripts/extract_ublock_lists.rb --output-dir /path/to/output
```

**Output** (`blocklists/ublock/`): `blocklist.txt`, `hosts.txt`, `allowlist.txt`, `sources.txt`

**Available filter lists:** `ublock-filters`, `ublock-badware`, `ublock-privacy`, `ublock-unbreak`, `easylist`, `easyprivacy`, `peter-lowe`, `urlhaus-malware`, `adguard-dns`, `steven-black-hosts`, `energized-basic`, `oisd-basic`

---

### `extract_privacy_badger_lists.rb`

Downloads EFF Privacy Badger seed data and converts it to Pi-hole format.

```sh
ruby scripts/extract_privacy_badger_lists.rb
ruby scripts/extract_privacy_badger_lists.rb --output-dir /etc/pihole/custom
ruby scripts/extract_privacy_badger_lists.rb --include-cookieblock
```

**Output** (`blocklists/privacy-badger/`): `blocklist.txt`, `hosts.txt`, `allowlist.txt`, `cookieblock.txt`, `sources.txt`

---

### `ai_review_blocklists.rb`

AI-powered blocklist/allowlist reviewer using a local Ollama model via DSPy. Scans blocklists for mainstream domains that should not be blocked, audits allowlists for suspicious domains, and generates `allowlists/general_allowlist_from_broad_blocklists.txt`.

Requires a running [Ollama](https://ollama.com) instance with a model loaded (default: `mistral`).

```sh
ruby scripts/ai_review_blocklists.rb
ruby scripts/ai_review_blocklists.rb --model llama3
ruby scripts/ai_review_blocklists.rb --host 192.168.1.10 --port 11434
ruby scripts/ai_review_blocklists.rb --batch 50
ruby scripts/ai_review_blocklists.rb --include-large   # include blocklists with >50k domains (slow)
ruby scripts/ai_review_blocklists.rb --dry-run         # skip writing the output allowlist file
```

---

### `update_all_lists.sh`

Runs all four update scripts in sequence.

```sh
bash scripts/update_all_lists.sh
```

---

## GitHub Actions

The workflow (`.github/workflows/update_lists.yml`) runs daily at 23:00 SAST and can be triggered manually via `workflow_dispatch`. Manual runs expose all key options as inputs.

**Default CI settings** (designed to avoid timeouts and IP blocks):
- `--read-timeout 5` — 5 s per HTTP attempt (vs 30 s default for local runs)
- `--skip-sources trendmicro,sophos` — both block GitHub datacenter IP ranges
- `--skip-sources socket_dev` (packages) — also blocks GitHub datacenter IP ranges

Override these via the `workflow_dispatch` inputs when running manually from a non-CI context.

---

## Cache Management

Cache files are git-ignored and stored in `scripts/`. They record which articles have been processed so incremental runs skip already-seen content.

### Reset a specific source from the domain scraper cache

```sh
ruby -e '
  require "json"
  f = "scripts/malicious_domains_cache.json"
  cache = JSON.parse(File.read(f))
  cache.delete("welivesecurity")
  File.write(f, JSON.pretty_generate(cache))
  puts "welivesecurity removed from cache"
'
```

### Reset a specific source from the package scraper cache

```sh
ruby -e '
  require "json"
  f = "scripts/malicious_packages_cache.json"
  cache = JSON.parse(File.read(f))
  cache.delete("socket_dev")
  File.write(f, JSON.pretty_generate(cache))
  puts "socket_dev removed from cache"
'
```

---

## Requirements

- Ruby 4.0+ (see `.ruby-version`)
- `bundle install` to install gem dependencies
- For OCR on images: Xcode Command Line Tools (macOS) or Tesseract (Linux)
- For OSSF full scans: set `GITHUB_TOKEN` env var for 5 000 req/hr (vs 60/hr unauthenticated)
- For `ai_review_blocklists.rb`: [Ollama](https://ollama.com) running locally with at least one model pulled

---

## License

See [LICENSES.md](LICENSES.md) for full license details covering original scripts, generated blocklists, and the malicious packages database.
