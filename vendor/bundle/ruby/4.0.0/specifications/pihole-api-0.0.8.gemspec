# -*- encoding: utf-8 -*-
# stub: pihole-api 0.0.8 ruby lib

Gem::Specification.new do |s|
  s.name = "pihole-api".freeze
  s.version = "0.0.8".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["trex22".freeze]
  s.bindir = "exe".freeze
  s.date = "1980-01-02"
  s.description = "A client for using the PiholeApi API in Ruby. Built form their api documentation. https://discourse.pi-hole.net/t/using-the-api/976/6. This is an unofficial project.".freeze
  s.email = ["contact@jasonchalom.com".freeze]
  s.homepage = "https://github.com/TRex22/pihole-api".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "3.6.9".freeze
  s.summary = "A client for using the PiholeApi API in Ruby.".freeze

  s.installed_by_version = "4.0.6".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<httparty>.freeze, [">= 0.22.0".freeze])
  s.add_runtime_dependency(%q<active_attr>.freeze, [">= 0.17.0".freeze])
  s.add_runtime_dependency(%q<nokogiri>.freeze, [">= 1.16.7".freeze])
  s.add_development_dependency(%q<rake>.freeze, ["~> 13.2.1".freeze])
  s.add_development_dependency(%q<minitest>.freeze, ["~> 5.25.1".freeze])
  s.add_development_dependency(%q<minitest-focus>.freeze, ["~> 1.4.0".freeze])
  s.add_development_dependency(%q<minitest-reporters>.freeze, ["~> 1.7.1".freeze])
  s.add_development_dependency(%q<timecop>.freeze, ["~> 0.9.10".freeze])
  s.add_development_dependency(%q<mocha>.freeze, ["~> 2.4.5".freeze])
  s.add_development_dependency(%q<pry>.freeze, ["~> 0.14.2".freeze])
  s.add_development_dependency(%q<webmock>.freeze, ["~> 3.23.1".freeze])
end
