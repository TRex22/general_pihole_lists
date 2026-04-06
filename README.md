# general_pihole_lists
My own pihole lists

# Scripts
## scrape_malicious_domains.rb
```
#Usage examples:
# Normal incremental (2 pages back overlap, default)
  ruby scripts/scrape_malicious_domains.rb

# Go back 14 days before the last cached article
  ruby scripts/scrape_malicious_domains.rb --lookback-days 14

# Full scan for 3 years + rescan all cached images for OCR
  ruby scripts/scrape_malicious_domains.rb --years 3 --rescan-images
```


## Reset cache for a given key
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
