# -*- encoding: utf-8 -*-
# stub: sorbet-struct-comparable 1.3.0 ruby lib

Gem::Specification.new do |s|
  s.name = "sorbet-struct-comparable".freeze
  s.version = "1.3.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "changelog_uri" => "https://github.com/bellroy/sorbet-struct-comparable/blob/master/CHANGELOG.md", "homepage_uri" => "https://github.com/bellroy/sorbet-struct-comparable", "source_code_uri" => "https://github.com/bellroy/sorbet-struct-comparable" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Bellroy Tech Team".freeze]
  s.bindir = "exe".freeze
  s.date = "1980-01-01"
  s.email = ["michael.webb@bellroy.com".freeze, "sam@samuelgil.es".freeze]
  s.homepage = "https://github.com/bellroy/sorbet-struct-comparable".freeze
  s.required_ruby_version = Gem::Requirement.new(">= 2.0.0".freeze)
  s.rubygems_version = "3.2.16".freeze
  s.summary = "Comparable T::Struct's for the equality focused typed Ruby developer.".freeze

  s.installed_by_version = "4.0.6".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<sorbet-runtime>.freeze, [">= 0.5".freeze])
  s.add_development_dependency(%q<bundler>.freeze, [">= 1.13".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 10.0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, [">= 3.0".freeze])
  s.add_development_dependency(%q<sorbet>.freeze, [">= 0.5".freeze])
end
