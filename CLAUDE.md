# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Pi-hole allowlist and blocklist collection with a Ruby script for extracting domains from uBlock Origin filter lists.

## Repository Structure

- `allowlists/` - Domain allowlists organized by service (whatsapp, apple, aws, claude, microsoft-productivity, general)
- `blocklists/` - Domain blocklists, including `ublock/` subdirectory for generated lists
- `scripts/` - Automation scripts

## Commands

### Generate uBlock Origin Blocklists

```bash
# Run with all default filter lists
ruby scripts/extract_ublock_lists.rb

# Show available filter lists
ruby scripts/extract_ublock_lists.rb --available

# Run with specific lists
ruby scripts/extract_ublock_lists.rb --lists easylist,easyprivacy,peter-lowe

# Custom output directory
ruby scripts/extract_ublock_lists.rb --output-dir /path/to/output
```

Output generates four files in `blocklists/ublock/`:
- `blocklist.txt` - Plain domain list
- `hosts.txt` - Hosts file format (0.0.0.0 prefix)
- `allowlist.txt` - Exception domains
- `sources.txt` - Source URLs reference

## List File Format

All list files use Pi-hole compatible format:
- One domain per line
- Comments start with `#`
- No wildcards (Pi-hole regex lists require separate handling)

## Available Filter List Sources

The Ruby script supports these sources: `ublock-filters`, `ublock-badware`, `ublock-privacy`, `ublock-unbreak`, `easylist`, `easyprivacy`, `peter-lowe`, `urlhaus-malware`, `adguard-dns`, `steven-black-hosts`, `energized-basic`, `oisd-basic`
