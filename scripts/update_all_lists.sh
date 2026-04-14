#!/usr/bin/env bash
# Run all update scripts
ruby ./scripts/extract_privacy_badger_lists.rb
ruby ./scripts/extract_ublock_lists.rb
ruby ./scripts/scrape_malicious_domains.rb
