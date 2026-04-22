# -*- encoding: utf-8 -*-
# stub: sorbet-result 1.4.0 ruby lib

Gem::Specification.new do |s|
  s.name = "sorbet-result".freeze
  s.version = "1.4.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "allowed_push_host" => "https://rubygems.org", "changelog_uri" => "https://github.com/maxveldink/sorbet-result/blob/main/CHANGELOG.md", "homepage_uri" => "https://github.com/maxveldink/sorbet-result", "rubygems_mfa_required" => "true", "source_code_uri" => "https://github.com/maxveldink/sorbet-result" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Max VelDink".freeze]
  s.bindir = "exe".freeze
  s.date = "1980-01-02"
  s.email = ["maxveldink@gmail.com".freeze]
  s.homepage = "https://github.com/maxveldink/sorbet-result".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.2".freeze)
  s.rubygems_version = "3.6.7".freeze
  s.summary = "Adds T::Result to sorbet-runtime, which is a basic, strongly-typed monad".freeze

  s.installed_by_version = "4.0.6".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<sorbet-runtime>.freeze, ["~> 0.5".freeze])
end
