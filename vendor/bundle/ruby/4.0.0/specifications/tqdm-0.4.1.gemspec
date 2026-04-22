# -*- encoding: utf-8 -*-
# stub: tqdm 0.4.1 ruby lib

Gem::Specification.new do |s|
  s.name = "tqdm".freeze
  s.version = "0.4.1".freeze

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Theodore Pak".freeze]
  s.date = "2023-01-01"
  s.description = "Enhances Enumerables to show progress while iterating. (Port of tqdm for Python.)".freeze
  s.email = ["theodore.r.pak@gmail.com".freeze]
  s.homepage = "https://github.com/powerpak/tqdm-ruby".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 1.9.2".freeze)
  s.rubygems_version = "3.1.6".freeze
  s.summary = "Enhances Enumerables to show progress while iterating.".freeze

  s.installed_by_version = "4.0.6".freeze

  s.specification_version = 4

  s.add_development_dependency(%q<bundler>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rake>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<sequel>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<sqlite3>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<rspec>.freeze, [">= 0".freeze])
  s.add_development_dependency(%q<timecop>.freeze, [">= 0".freeze])
end
