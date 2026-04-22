# -*- encoding: utf-8 -*-
# stub: sorbet-baml 0.5.1 ruby lib

Gem::Specification.new do |s|
  s.name = "sorbet-baml".freeze
  s.version = "0.5.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "changelog_uri" => "https://github.com/vicentereig/sorbet-baml/blob/main/CHANGELOG.md", "homepage_uri" => "https://github.com/vicentereig/sorbet-baml", "source_code_uri" => "https://github.com/vicentereig/sorbet-baml" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Vicente Reig Rincon de Arellano".freeze]
  s.bindir = "exe".freeze
  s.date = "2026-03-07"
  s.description = "A Ruby gem that converts T::Struct and T::Enum to BAML (Boundary AI Markup Language) type definitions. BAML uses 60% fewer tokens than JSON Schema while maintaining type safety.".freeze
  s.email = ["hey@vicente.services".freeze]
  s.homepage = "https://github.com/vicentereig/sorbet-baml".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.3.0".freeze)
  s.rubygems_version = "3.6.5".freeze
  s.summary = "Convert Sorbet types to BAML type definitions for LLM prompting".freeze

  s.installed_by_version = "4.0.6".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<sorbet-runtime>.freeze, ["~> 0.5".freeze])
end
