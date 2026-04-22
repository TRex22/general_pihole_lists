# -*- encoding: utf-8 -*-
# stub: sorbet-toon 0.1.0 ruby lib

Gem::Specification.new do |s|
  s.name = "sorbet-toon".freeze
  s.version = "0.1.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "documentation_uri" => "https://github.com/vicentereig/dspy.rb/blob/main/lib/sorbet/toon/README.md", "homepage_uri" => "https://github.com/vicentereig/dspy.rb/blob/main/lib/sorbet/toon/README.md" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Vicente Reig Rinc\u00F3n de Arellano".freeze]
  s.date = "1980-01-02"
  s.description = "Ruby port of the TOON encoder/decoder used inside DSPy.rb. Provides Sorbet-aware normalization, reconstruction, and prompt-ready helpers so signatures can round-trip through TOON without hand-written serializers.".freeze
  s.email = ["hey@vicente.services".freeze]
  s.homepage = "https://github.com/vicentereig/dspy.rb/blob/main/lib/sorbet/toon/README.md".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.1".freeze)
  s.rubygems_version = "3.6.9".freeze
  s.summary = "TOON encode/decode pipeline for Sorbet signatures.".freeze

  s.installed_by_version = "4.0.6".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<sorbet-runtime>.freeze, ["~> 0.5".freeze])
end
