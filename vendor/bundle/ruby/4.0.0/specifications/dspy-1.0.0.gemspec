# -*- encoding: utf-8 -*-
# stub: dspy 1.0.0 ruby lib

Gem::Specification.new do |s|
  s.name = "dspy".freeze
  s.version = "1.0.0".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Vicente Reig Rinc\u00F3n de Arellano".freeze]
  s.date = "1980-01-02"
  s.description = "The Ruby framework for programming with large language models. DSPy.rb brings structured LLM programming to Ruby developers. Instead of wrestling with prompt strings and parsing responses, you define typed signatures using idiomatic Ruby to compose and decompose AI Worklows and AI Agents.".freeze
  s.email = ["hey@vicente.services".freeze]
  s.homepage = "https://github.com/vicentereig/dspy.rb".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.3.0".freeze)
  s.rubygems_version = "3.6.9".freeze
  s.summary = "The Ruby framework for programming\u2014rather than prompting\u2014language models.".freeze

  s.installed_by_version = "4.0.6".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<dry-configurable>.freeze, ["~> 1.0".freeze])
  s.add_runtime_dependency(%q<dry-logger>.freeze, ["~> 1.0".freeze])
  s.add_runtime_dependency(%q<async>.freeze, ["~> 2.29".freeze])
  s.add_runtime_dependency(%q<concurrent-ruby>.freeze, ["~> 1.3".freeze])
  s.add_runtime_dependency(%q<sorbet-runtime>.freeze, ["~> 0.5".freeze])
  s.add_runtime_dependency(%q<sorbet-schema>.freeze, ["~> 0.3".freeze])
  s.add_runtime_dependency(%q<sorbet-baml>.freeze, ["~> 0.5".freeze, ">= 0.5.1".freeze])
  s.add_runtime_dependency(%q<sorbet-toon>.freeze, ["~> 0.1".freeze])
  s.add_runtime_dependency(%q<dspy-schema>.freeze, ["~> 1.0.0".freeze])
end
