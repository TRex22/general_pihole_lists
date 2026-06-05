# frozen_string_literal: true
# OSSF Malicious Packages scraper
#
# Source: https://github.com/ossf/malicious-packages
# Directory layout:
#   osv/{status}/{ecosystem}/{package-name}/MAL-*.json
#   status dirs:    malicious, unmergable, withdrawn
#   ecosystem dirs: npm, PyPI, RubyGems, crates.io, NuGet, Go, Maven, etc.
#
# Uses the Git Trees API (not Contents API) to enumerate package paths
# efficiently. Each ecosystem is resolved in one recursive tree call rather than
# paginating through its directory — this keeps total API calls well under the
# unauthenticated rate limit (60 req/hr).
#
# With GITHUB_TOKEN set, the rate limit rises to 5 000 req/hr.

OSSF_REPO_BASE = 'https://api.github.com/repos/ossf/malicious-packages'

# Normalises OSSF directory names to canonical ecosystem labels.
# Includes both the capitalised forms (repo README) and lowercase forms
# (actual directory names observed in the repo tree).
OSSF_ECOSYSTEM_MAP = {
  'PyPI'           => 'PyPI',  'pypi'           => 'PyPI',
  'npm'            => 'npm',
  'RubyGems'       => 'RubyGems', 'rubygems'    => 'RubyGems',
  'crates.io'      => 'Cargo',    'cargo'       => 'Cargo',
  'NuGet'          => 'NuGet',    'nuget'       => 'NuGet',
  'Go'             => 'Go',       'go'          => 'Go',
  'Maven'          => 'Maven',    'maven'       => 'Maven',
  'GitHub Actions' => 'GitHub Actions', 'github-actions' => 'GitHub Actions',
  'Packagist'      => 'Packagist', 'packagist'  => 'Packagist',
  'Hex'            => 'Hex',      'hex'         => 'Hex',
  'Hex.pm'         => 'Hex',
  'SwiftURL'       => 'Swift',    'swift'       => 'Swift',
  'CocoaPods'      => 'CocoaPods', 'cocoapods'  => 'CocoaPods',
  'Pub'            => 'Pub',      'pub'         => 'Pub',
  'OSS-Fuzz'       => 'OSS-Fuzz',
  'GHSAdb'         => 'GHSAdb',
}.freeze

class OSSFPackageScraper < PackageBaseScraper
  SOURCE_NAME = 'OSSF Malicious Packages'
  SOURCE_KEY  = 'ossf'

  def run
    puts "Source : #{SOURCE_NAME}"
    puts "Repo   : https://github.com/ossf/malicious-packages"
    puts "Cache  : #{@cache_file}"
    auth = ENV['GITHUB_TOKEN']&.match?(/\S/) ? 'yes (GITHUB_TOKEN set)' : 'no (60 req/hr — set GITHUB_TOKEN for 5000/hr)'
    puts "GitHub auth : #{auth}"
    puts

    all_packages = fetch_all_packages
    puts "  Total packages in repo : #{all_packages.size}"

    new_count = 0
    all_packages.each do |pkg|
      cache_key = "ossf:#{pkg[:status]}/#{pkg[:type]}/#{pkg[:name]}"
      next if @cache['articles'][cache_key]

      @cache['articles'][cache_key] = {
        'url'                 => "https://github.com/ossf/malicious-packages/tree/main/osv/#{pkg[:status]}/#{pkg[:raw_ecosystem]}/#{pkg[:raw_name]}",
        'title'               => "#{pkg[:type]}/#{pkg[:name]}",
        'date'                => nil,
        'scraped_at'          => Time.now.utc.iso8601,
        'packages'            => [{ 'name' => pkg[:name], 'type' => pkg[:type] }],
        'written_to_database' => false
      }
      @pending[cache_key] = { packages: [{ 'name' => pkg[:name], 'type' => pkg[:type] }] }
      new_count += 1
    end

    puts "  New entries added to cache : #{new_count}"
    puts "  Total cache entries        : #{@cache['articles'].size}"

    save_cache unless @dry_run
    pkg_print_summary
  end

  private

  def request_headers
    h = {
      'Accept'     => 'application/vnd.github.v3+json',
      'User-Agent' => 'pihole-list-builder/1.0'
    }
    h['Authorization'] = "token #{ENV['GITHUB_TOKEN']}" if ENV['GITHUB_TOKEN']&.match?(/\S/)
    h
  end

  # Navigate the git tree from the main branch tip to enumerate all packages.
  # Total API calls: ~2 + N_status + N_status * N_ecosystems ≈ 35 (under 60/hr limit).
  def fetch_all_packages
    packages = []

    # Step 1: resolve main branch → commit SHA → root tree SHA
    branch_info = api_get("#{OSSF_REPO_BASE}/branches/main")
    return packages unless branch_info

    root_sha = branch_info.dig('commit', 'sha')
    return packages unless root_sha

    # Step 2: root tree → osv/ subtree SHA
    osv_sha = find_tree_sha(root_sha, 'osv')
    return packages unless osv_sha

    # Step 3: osv/ tree → status dirs (malicious, unmergable, withdrawn)
    status_items = tree_items(osv_sha)
    return packages unless status_items

    puts "  Status dirs : #{status_items.select { |i| i['type'] == 'tree' }.map { |i| i['path'] }.join(', ')}"

    status_items.select { |i| i['type'] == 'tree' }.each do |status_item|
      status   = status_item['path']
      eco_list = tree_items(status_item['sha'])
      next unless eco_list

      eco_list.select { |i| i['type'] == 'tree' }.each do |eco_item|
        eco_name = eco_item['path']
        norm_eco = OSSF_ECOSYSTEM_MAP[eco_name] || eco_name
        puts "    #{status}/#{eco_name}..."

        # One recursive tree call for the entire ecosystem — gets all package paths
        all_blobs = tree_recursive(eco_item['sha'])
        next unless all_blobs

        # Extract unique package names from paths like:
        #   "pkg-name/MAL-2024-1234.json"              → pkg-name
        #   "@scope/scoped-pkg/MAL-2024-5678.json"     → @scope/scoped-pkg
        pkg_names = all_blobs
          .select { |i| i['type'] == 'blob' && i['path'].include?('/') }
          .map do |i|
            parts = i['path'].split('/')
            if eco_name == 'npm' && parts.first.start_with?('@')
              "#{parts[0]}/#{parts[1]}"
            else
              parts.first
            end
          end
          .uniq

        puts "      #{pkg_names.size} packages"

        pkg_names.each do |pkg_name|
          packages << {
            name:          pkg_name,
            type:          norm_eco,
            status:        status,
            raw_ecosystem: eco_name,
            raw_name:      pkg_name
          }
        end
      end
    end

    packages.uniq { |p| "#{p[:status]}::#{p[:type]}::#{p[:name].downcase}" }
  end

  def find_tree_sha(parent_sha, name)
    items = tree_items(parent_sha)
    items&.find { |i| i['path'] == name && i['type'] == 'tree' }&.dig('sha')
  end

  def tree_items(sha)
    data = api_get("#{OSSF_REPO_BASE}/git/trees/#{sha}")
    data&.dig('tree')
  end

  def tree_recursive(sha)
    data = api_get("#{OSSF_REPO_BASE}/git/trees/#{sha}?recursive=1")
    return nil unless data
    warn "  Warning: tree truncated (sha=#{sha[0, 8]}…)" if data['truncated']
    data['tree']
  end

  def api_get(url)
    resp = fetch_with_retry(url)
    return nil unless resp&.success?
    JSON.parse(resp.body)
  rescue JSON::ParserError
    nil
  end
end
