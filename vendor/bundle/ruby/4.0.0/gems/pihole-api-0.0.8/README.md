# PiholeApiClient
A client for the PiholeApi API.

See:
- https://discourse.pi-hole.net/t/pi-hole-api/1863
- https://www.reddit.com/r/pihole/comments/br5tla/how_to_get_info_from_the_new_restful_api/
- https://pi-hole.net/blog/2022/11/17/upcoming-changes-authentication-for-more-api-endpoints-required/
- https://pi-hole.net/blog/2022/12/21/pi-hole-ftl-v5-20-and-web-v5-18-released/
- https://github.com/pi-hole/AdminLTE/issues/2470
- https://github.com/pi-hole/AdminLTE/issues/2326
- https://discourse.pi-hole.net/t/using-the-api/976/6

This is an unofficial project and still a work in progress (WIP) ... more to come soon.

## TODO
- Login and Auth token generation: `admin/scripts/pi-hole/php/api_token.php`
- Undocumented endpoints
- Undocumented filters for getAllQueries
- Generate WebPassword Hash
- getAllQueries allow client input

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'pihole-api'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install pihole-api

## Usage

```ruby
  require 'pihole-api'
  client = PiholeApi::Client.new(base_path: 'http://localhost:80/', api_token: api_token, port: 80)

  # Some example calls
  client.type
```

Double hash web password to get the api_token.
A helper method exists on the client to do this:
```ruby
require 'pihole-api'
api_token = PiholeApi::Client.hash_password(password)
end
```

However the client now generates the API token automatically from the given password

### Endpoints
#### Authorised
- `summary_raw`
- `summary(params: {})`
- `over_time_data_10_mins`
- `top_items(number_of_items=10)`
- `get_query_sources(number_of_items=10)`
- `top_clients(number_of_items=10)`
- `get_forward_destinations`
- `get_query_types`
- `get_all_queries(params: {}, from_time: nil, until_time: nil, latest_number_of_items: nil)`
- `recent_blocked`
- `enable`
- `disable`
#### Authorised Non API
- auth_form_token
- `teleport(whitelist: true, regex_whitelist: true, blacklist: true, regexlist: true, adlist: true, client: true, group: true, auditlog: true, staticdhcpleases: true, localdnsrecords: true, localcnamerecords: true, flushtables: true)`

#### Unauthorised
- `type`
- `version`

### Constants
  Constants

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

### Tests
To run tests execute:

    $ rake test

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/trex22/pihole-api. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the pihole-api: project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/trex22/pihole-api/blob/master/CODE_OF_CONDUCT.md).
