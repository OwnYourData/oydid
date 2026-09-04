#!/usr/bin/env ruby -rubygems
# -*- encoding: utf-8 -*-

Gem::Specification.new do |gem|
    gem.version               = File.read('VERSION').chomp
    gem.date                  = File.mtime('VERSION').strftime('%Y-%m-%d')

    gem.name                  = "oydid"
    gem.homepage              = "http://github.com/ownyourdata/oydid"
    gem.license               = 'Apache-2.0'
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
    gem.test_files            = Dir.glob('spec/**/*.rb') + Dir.glob('spec/**/*.json') + Dir.glob('spec/**/*.doc')

    # 3.2 is what CI tests and what the service images run; the hard floor
    # from dependencies is 3.1 (securerandom ~> 0.4.1)
    gem.required_ruby_version = '>= 3.2.0'
    gem.requirements          = []
    gem.add_dependency 'simple_dag',            '~> 0.0.1'
    gem.add_dependency 'stringio',              '~> 3.2.0'
    # >= 3.2 is required: jwt < 3.2.0 (and < 2.10.3) accepts an empty HMAC
    # key, i.e. anybody can forge an HS256 token - CVE-2026-45363.
    gem.add_dependency 'jwt',                   '>= 3.2', '< 4'
    gem.add_dependency 'jwt-eddsa',             '~> 0.9.0'
    gem.add_dependency 'rdf',                   '~> 3.3.4'
    gem.add_dependency 'rdf-normalize',         '~> 0.7.0'
    # >= 2.19.9 is required: format string injection in the parser
    # (CVE-2026-33210) and a heap overflow when generating into an IO
    # (CVE-2026-54696) are only fixed from there on.
    gem.add_dependency 'json',                  '>= 2.19.9', '< 3'
    gem.add_dependency 'json-ld',               '~> 3.3.2'
    gem.add_dependency 'rbnacl',                '~> 7.1.2'
    gem.add_dependency 'ed25519',               '~> 1.4.0'
    gem.add_dependency 'openssl',               '~> 3.3.2'
    gem.add_dependency 'httparty',              '~> 0.24'
    gem.add_dependency 'multibases',            '~> 0.3.2'
    gem.add_dependency 'multicodecs',           '~> 1.0.0'
    gem.add_dependency 'securerandom',          '~> 0.4.1'
    gem.add_dependency 'json-canonicalization', '~> 1.0.0'


    gem.add_development_dependency 'rspec',     '~> 3.10'

    gem.post_install_message = nil
end