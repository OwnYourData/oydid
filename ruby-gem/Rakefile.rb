#!/usr/bin/env ruby
$:.unshift(File.expand_path(File.join(File.dirname(__FILE__), 'lib')))
require 'rubygems'

namespace :gem do
  desc "Build the oydid-#{File.read('VERSION').chomp}.gem file"
  task :build do
    sh "gem build oydid.gemspec && mv oydid-#{File.read('VERSION').chomp}.gem pkg/"
  end

  desc "Release the oydid-#{File.read('VERSION').chomp}.gem file"
  task :release do
    sh "gem push pkg/oydid-#{File.read('VERSION').chomp}.gem"
  end
end

desc 'Default: run specs.'
task default: :spec
task specs: :spec

require 'rspec/core/rake_task'
desc 'Run specifications'
RSpec::Core::RakeTask.new do |spec|
  spec.rspec_opts = %w(--options spec/spec.opts) if File.exists?('spec/spec.opts')
end

desc "Run specifications for continuous integration"
RSpec::Core::RakeTask.new("spec:ci") do |spec|
  spec.rspec_opts = %w(--options spec/spec.opts) if File.exists?('spec/spec.opts')
end
