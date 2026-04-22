# -*- encoding: utf-8 -*-
# stub: dspy-schema 1.0.2 ruby lib

Gem::Specification.new do |s|
  s.name = "dspy-schema".freeze
  s.version = "1.0.2".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "github_repo" => "git@github.com:vicentereig/dspy.rb" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Vicente Reig Rinc\u00F3n de Arellano".freeze]
  s.date = "1980-01-02"
  s.description = "Provides DSPy::TypeSystem::SorbetJsonSchema without requiring the full DSPy stack, enabling reuse in sibling gems and downstream projects.".freeze
  s.email = ["hey@vicente.services".freeze]
  s.homepage = "https://github.com/vicentereig/dspy.rb".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.3.0".freeze)
  s.rubygems_version = "3.6.9".freeze
  s.summary = "Sorbet to JSON Schema conversion utilities reused by DSPy.rb.".freeze

  s.installed_by_version = "4.0.6".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<sorbet-runtime>.freeze, [">= 0.5.0".freeze])
end
