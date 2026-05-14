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

## Regex and Plain Domain Policy

When a regex pattern is added to `regex_allowlist.txt` (e.g. `(^|\.)sharepoint\.com$`), do **NOT** remove the corresponding explicit domain entries from the plain allowlist files. Both must coexist because:
- Plain entries work on Pi-hole instances without regex allowlist support
- Plain entries document intent and are self-describing
- Plain entries match faster than regex patterns
- Plain entries survive regex file misconfiguration

Example: `sharepoint.com` stays in `microsoft-productivity.txt` even though `(^|\.)sharepoint\.com$` is in `regex_allowlist.txt`.

## Available Filter List Sources

The Ruby script supports these sources: `ublock-filters`, `ublock-badware`, `ublock-privacy`, `ublock-unbreak`, `easylist`, `easyprivacy`, `peter-lowe`, `urlhaus-malware`, `adguard-dns`, `steven-black-hosts`, `energized-basic`, `oisd-basic`
