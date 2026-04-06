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
