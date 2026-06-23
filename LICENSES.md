# License Attribution

This document provides license information for all components of this repository.

---

## Original Content (MIT License)

The following components are original work by Jason Chalom and licensed under the MIT License:

- **Scripts**: All files in `scripts/` directory
- **Manually-curated allowlists**: All files in `allowlists/` directory
  - `allowlists/apple.txt` (domains sourced from [Pi-hole Commonly Whitelisted Domains](https://discourse.pi-hole.net/t/commonly-whitelisted-domains/212) and [Apple Enterprise Network Requirements](https://support.apple.com/en-us/101555))
  - `allowlists/aws.txt`
  - `allowlists/ai-services.txt`
  - `allowlists/general.txt`
  - `allowlists/microsoft-productivity.txt`
  - `allowlists/whatsapp.txt`
- **Documentation**: `README.md`, `CLAUDE.md`, and other documentation files

See [LICENSE](LICENSE) for the full MIT License text.

---

## Generated Blocklists — uBlock Origin Sources (Third-Party Licenses)

Files in `blocklists/ublock/` are generated from third-party filter lists. These generated files inherit the licenses of their source materials. **If you redistribute these files, you must comply with the original source licenses.**

| Source | License | URL |
|--------|---------|-----|
| **uBlock Origin Filters** | GPLv3 | https://github.com/uBlockOrigin/uAssets |
| **uBlock Badware Risks** | GPLv3 | https://github.com/uBlockOrigin/uAssets |
| **uBlock Privacy** | GPLv3 | https://github.com/uBlockOrigin/uAssets |
| **uBlock Unbreak** | GPLv3 | https://github.com/uBlockOrigin/uAssets |
| **EasyList** | GPLv3 or CC-BY-SA 3.0 | https://easylist.to |
| **EasyPrivacy** | GPLv3 or CC-BY-SA 3.0 | https://easylist.to |
| **AdGuard DNS Filter** | GPLv3 | https://github.com/AdguardTeam/AdGuardSDNSFilter |
| **Peter Lowe's Ad and Tracking Server List** | No explicit license (public list) | https://pgl.yoyo.org/adservers/ |
| **OISD Basic** | No explicit license | https://oisd.nl |
| **Steven Black Hosts** | MIT | https://github.com/StevenBlack/hosts |
| **URLhaus Malware Filter** | CC0 1.0 (Public Domain) | https://urlhaus.abuse.ch |
| **Energized Basic** | MIT | https://energized.pro |

---

## Generated Blocklists — Privacy Badger Source

Files in `blocklists/privacy-badger/` are generated from EFF Privacy Badger seed data.

| Source | License | URL |
|--------|---------|-----|
| **EFF Privacy Badger seed data** | GPLv3+ | https://github.com/EFForg/privacybadger |

The Privacy Badger browser extension and its seed data are licensed under the GNU General Public License v3.0 or later by the Electronic Frontier Foundation (EFF). Generated files in `blocklists/privacy-badger/` are derivative works and must comply with GPLv3+ if redistributed.

---

## Malicious Packages Database — Source Licenses

Files in `malicious_package_database/` (`malicious_packages.json`, `malicious_packages.csv`) aggregate data from multiple sources. The database as a compilation is licensed under the MIT License, but data derived from specific sources carries their original licenses.

### Structured Data Sources

#### OSSF Malicious Packages

| Attribute | Detail |
|-----------|--------|
| **Source** | https://github.com/ossf/malicious-packages |
| **Maintainer** | Open Source Security Foundation (OpenSSF) |
| **License** | Apache License 2.0 |
| **License URL** | https://github.com/ossf/malicious-packages/blob/main/LICENSE |
| **Data accessed via** | GitHub Git Trees API |
| **Attribution required** | Yes — Apache 2.0 requires retention of copyright notices |

The OSSF malicious-packages database is maintained by the OpenSSF and licensed under Apache 2.0. Package entries derived from this source carry the Apache 2.0 terms. When redistributing database entries that originate from OSSF, include the following attribution:

> Malicious package data sourced from the OSSF Malicious Packages database
> (https://github.com/ossf/malicious-packages), licensed under Apache 2.0.

### Security Blog Sources (Scraped)

The following sources are scraped for package mentions in publicly available security research articles. Only factual data (package names, package types, and source URLs) is extracted and stored — no article text is reproduced. Facts are not copyrightable; attribution is provided via the `sources` array in each database entry.

| Source | Website | Notes |
|--------|---------|-------|
| Socket.dev Security Research | https://socket.dev/blog | Dedicated malicious-package research blog |
| Sonatype Security Research | https://www.sonatype.com/blog | Supply chain security research |
| Checkmarx Supply Chain Security | https://checkmarx.com/blog/ | WordPress REST API |
| JFrog Security Research | https://jfrog.com/blog/tag/security-research/ | Sitemap-based discovery |
| Snyk Security Research | https://snyk.io/blog/ | Supply chain and vulnerability research |
| Aqua Security (Team Nautilus) | https://www.aquasec.com/blog/ | Container and supply chain security |
| The Hacker News | https://thehackernews.com | General security news |
| BleepingComputer | https://www.bleepingcomputer.com | General security news |
| Cisco Talos Intelligence | https://blog.talosintelligence.com | Threat intelligence |
| Palo Alto Unit 42 | https://unit42.paloaltonetworks.com | Threat intelligence |
| Kaspersky Securelist | https://securelist.com | Threat intelligence |
| Microsoft Security Blog | https://www.microsoft.com/en-us/security/blog/ | Threat intelligence |
| Google Cloud Threat Intelligence | https://cloud.google.com/blog/topics/threat-intelligence | Threat intelligence (RSS) |

Each database entry includes a `sources` array listing the original article URL, title, and date for full traceability.

---

## License Summaries

### Apache License 2.0
- Applies to: OSSF Malicious Packages data
- Key requirements: Retain copyright and license notices; document modifications
- Full text: https://www.apache.org/licenses/LICENSE-2.0

### GPLv3 (GNU General Public License v3.0)
- Applies to: uBlock Origin lists, EasyList, EasyPrivacy, AdGuard DNS Filter, Privacy Badger
- Key requirement: Derivative works must also be licensed under GPLv3
- Full text: https://www.gnu.org/licenses/gpl-3.0.html

### CC-BY-SA 3.0 (Creative Commons Attribution-ShareAlike 3.0)
- Applies to: EasyList, EasyPrivacy (dual-licensed option)
- Key requirements: Attribution required; derivative works must use same license
- Full text: https://creativecommons.org/licenses/by-sa/3.0/

### CC0 1.0 (Public Domain)
- Applies to: URLhaus Malware Filter
- No restrictions on use
- Full text: https://creativecommons.org/publicdomain/zero/1.0/

### MIT License
- Applies to: Original scripts, allowlists, documentation; Steven Black Hosts; Energized Basic
- Permissive license, compatible with this project
- Full text: https://opensource.org/licenses/MIT

---

## Compliance Notes

### For `blocklists/ublock/` and `blocklists/privacy-badger/`

**For personal use:** No restrictions apply.

**For redistribution:** The presence of GPLv3-licensed content means:
- You must make source available
- You must include license notices
- Derivative works must be GPLv3-compatible

To avoid copyleft requirements, generate blocklists from MIT/CC0 sources only:
```bash
ruby scripts/extract_ublock_lists.rb --lists steven-black-hosts,urlhaus-malware,energized-basic
```

### For `malicious_package_database/malicious_packages.*`

**For personal use:** No restrictions apply.

**For redistribution:** Include attribution for the OSSF-derived entries per Apache 2.0. The `sources` array in each entry identifies the originating source for traceability.

---

## Acknowledgments

This project gratefully acknowledges the maintainers of all sources used:

- Raymond Hill and the uBlock Origin team
- The EasyList authors
- AdGuard team
- Peter Lowe
- OISD maintainers
- Steven Black
- abuse.ch (URLhaus)
- Energized Protection team
- Electronic Frontier Foundation (Privacy Badger)
- OpenSSF Malicious Packages contributors
- Socket.dev security research team
- Sonatype security research team
- Checkmarx security research team
- JFrog security research team
- Snyk security research team
- Aqua Security Team Nautilus
- The Hacker News
- BleepingComputer
- Cisco Talos Intelligence
- Palo Alto Unit 42
- Kaspersky Securelist
- Microsoft Security Response Center
- Google Cloud / Mandiant Threat Intelligence

Their work in maintaining security intelligence benefits the entire community.
