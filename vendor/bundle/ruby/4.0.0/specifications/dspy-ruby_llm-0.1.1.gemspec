# -*- encoding: utf-8 -*-
# stub: dspy-ruby_llm 0.1.1 ruby lib

Gem::Specification.new do |s|
  s.name = "dspy-ruby_llm".freeze
  s.version = "0.1.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "github_repo" => "git@github.com:vicentereig/dspy.rb" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Vicente Reig Rinc\u00F3n de Arellano".freeze, "Kieran Klaassen".freeze]
  s.date = "1980-01-02"
  s.description = "Provides a unified adapter using RubyLLM to access OpenAI, Anthropic, Gemini, Bedrock, Ollama, and more through a single interface in DSPy.rb projects.".freeze
  s.email = ["hey@vicente.services".freeze, "kieranklaassen@gmail.com".freeze]
  s.homepage = "https://github.com/vicentereig/dspy.rb".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 3.3.0".freeze)
  s.rubygems_version = "3.6.9".freeze
  s.summary = "RubyLLM adapter for DSPy.rb - unified access to 12+ LLM providers.".freeze

  s.installed_by_version = "4.0.6".freeze

  s.specification_version = 4

  s.add_runtime_dependency(%q<dspy>.freeze, [">= 0.30.1".freeze, "< 2.0".freeze])
  s.add_runtime_dependency(%q<ruby_llm>.freeze, [">= 1.14.1".freeze, "< 2.0".freeze])
end
