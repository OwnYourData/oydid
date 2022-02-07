#!/usr/bin/env ruby -rubygems
# -*- encoding: utf-8 -*-

Gem::Specification.new do |gem|
    gem.version               = File.read('VERSION').chomp
    gem.date                  = File.mtime('VERSION').strftime('%Y-%m-%d')

    gem.name                  = "oydid"
    gem.homepage              = "http://github.com/ownyourdata/oydid"
    gem.license               = 'MIT'
    gem.summary               = "Own Your Decentralized Identifier for Ruby."
    gem.description           = "This gem provides the basic methods for managing did:oyd."
    gem.metadata           = {
        "documentation_uri" => "https://ownyourdata.github.io/oydid",
        "bug_tracker_uri"   => "https://github.com/ownyourdata/oydid/issues",
        "homepage_uri"      => "http://github.com/ownyourdata/oydid",
        "source_code_uri"   => "http://github.com/ownyourdata/oydid/tree/main/ruby-gem",
    }

    gem.authors               = ['Christoph Fabianek']

    gem.platform              = Gem::Platform::RUBY
    gem.files                 = %w(AUTHORS README.md LICENSE VERSION) + Dir.glob('lib/**/*.rb')
    gem.test_files            = Dir.glob('spec/**/*.rb') + Dir.glob('spec/**/*.json')

    gem.required_ruby_version = '>= 2.5.7'
    gem.requirements          = []
    gem.add_dependency             'multibases', '~> 0.3.2'
    gem.add_development_dependency 'rspec',      '~> 3.10'
    gem.add_development_dependency 'yard' ,      '~> 0.9'

    gem.post_install_message  = nil
end