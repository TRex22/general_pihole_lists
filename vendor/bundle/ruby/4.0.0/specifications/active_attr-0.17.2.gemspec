# -*- encoding: utf-8 -*-
# stub: active_attr 0.17.2 ruby lib

Gem::Specification.new do |s|
  s.name = "active_attr".freeze
  s.version = "0.17.2".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "changelog_uri" => "https://github.com/cgriego/active_attr/blob/master/CHANGELOG.md" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Chris Griego".freeze, "Ben Poweski".freeze]
  s.date = "1980-01-02"
  s.description = "Create plain old Ruby models without reinventing the wheel.".freeze
  s.email = ["cgriego@gmail.com".freeze, "bpoweski@gmail.com".freeze]
  s.homepage = "https://github.com/cgriego/active_attr".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.1.0".freeze)
  s.rubygems_version = "3.6.9".freeze
  s.summary = "What ActiveModel left out".freeze

  s.installed_by_version = "4.0.6".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<actionpack>.freeze, [">= 3.0.2".freeze, "< 8.2".freeze])
  s.add_runtime_dependency(%q<activemodel>.freeze, [">= 3.0.2".freeze, "< 8.2".freeze])
  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 3.0.2".freeze, "< 8.2".freeze])
  s.add_development_dependency(%q<bundler>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<factory_bot>.freeze, ["< 7.0".freeze])
  s.add_development_dependency(%q<minitest>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0.9.0".freeze, "< 13.3".freeze])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.0".freeze])
  s.add_development_dependency(%q<tzinfo>.freeze, [">= 0".freeze])
end
