# License Attribution

This document provides license information for all components of this repository.

## Original Content (MIT License)

The following components are original work by Jason Chalom and licensed under the MIT License:

- **Scripts**: All files in `scripts/` directory
- **Manually-curated allowlists**: All files in `allowlists/` directory
  - `allowlists/apple.txt`
  - `allowlists/aws.txt`
  - `allowlists/claude.txt`
  - `allowlists/general.txt`
  - `allowlists/microsoft-productivity.txt`
  - `allowlists/whatsapp.txt`
- **Documentation**: `README.md`, `CLAUDE.md`, and other documentation files

See [LICENSE](LICENSE) for the full MIT License text.

---

## Generated Blocklists (Third-Party Licenses)

Files in `blocklists/ublock/` are generated from third-party filter lists. These generated files inherit the licenses of their source materials. **If you redistribute these files, you must comply with the original source licenses.**

### Source Filter Lists

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

### License Summaries

#### GPLv3 (GNU General Public License v3.0)
- Applies to: uBlock Origin lists, EasyList, EasyPrivacy, AdGuard DNS Filter
- Key requirement: Derivative works must also be licensed under GPLv3
- Full text: https://www.gnu.org/licenses/gpl-3.0.html

#### CC-BY-SA 3.0 (Creative Commons Attribution-ShareAlike 3.0)
- Applies to: EasyList, EasyPrivacy (dual-licensed option)
- Key requirements: Attribution required, derivative works must use same license
- Full text: https://creativecommons.org/licenses/by-sa/3.0/

#### CC0 1.0 (Public Domain)
- Applies to: URLhaus Malware Filter
- No restrictions on use
- Full text: https://creativecommons.org/publicdomain/zero/1.0/

#### MIT License
- Applies to: Steven Black Hosts, Energized Basic
- Permissive license, compatible with this project's MIT license
- Full text: https://opensource.org/licenses/MIT

---

## Compliance Notes

When using or redistributing the **generated blocklists** (`blocklists/ublock/`):

1. **For personal use**: No restrictions apply.

2. **For redistribution**: The presence of GPLv3-licensed content means:
   - You must make source available
   - You must include license notices
   - Derivative works must be GPLv3-compatible

3. **To avoid copyleft requirements**: Use only MIT/CC0 compatible sources by running:
   ```bash
   ruby scripts/extract_ublock_lists.rb --lists steven-black-hosts,urlhaus-malware,energized-basic
   ```

---

## Acknowledgments

This project gratefully acknowledges the maintainers of all the filter lists used:

- Raymond Hill and the uBlock Origin team
- The EasyList authors
- AdGuard team
- Peter Lowe
- OISD maintainers
- Steven Black
- abuse.ch (URLhaus)
- Energized Protection team

Their work in maintaining comprehensive filter lists benefits the entire internet community.
