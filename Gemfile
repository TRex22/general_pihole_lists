# frozen_string_literal: true

source 'https://rubygems.org'

ruby '~> 4.0'

# HTTP client — used by all scrapers and test scripts
gem 'httparty', '~> 0.24'

# HTML parsing — article and listing page extraction
gem 'nokogiri', '~> 1.19'

# TLD validation against the Mozilla Public Suffix List
gem 'public_suffix', '~> 7.0'

# Progress bars — used in scrape_malicious_domains.rb
gem 'tqdm', '~> 0.4'

# DSPy for Ruby — AI-powered blocklist/allowlist review (scripts/ai_review_blocklists.rb)
gem 'dspy', '~> 1.0.0'
gem 'dspy-ruby_llm', '~> 0.1.1'

# json is a default gem bundled with Ruby — no explicit version needed
gem 'oj', '~> 3.17'

# csv became a bundled gem in Ruby 3.4 — must be declared explicitly
gem 'csv', '~> 3.3'

# benchmark became a bundled gem in Ruby 3.4 — must be declared explicitly
gem 'benchmark', '~> 0.5.0'

# Pi-hole API client — used by scripts/extract_pihole_logs.rb
gem 'pihole-api', '~> 0.0.8'
