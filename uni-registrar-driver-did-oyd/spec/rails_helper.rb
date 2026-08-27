require 'spec_helper'
ENV['RAILS_ENV'] ||= 'test'
require_relative '../config/environment'

abort("The Rails environment is running in production mode!") if Rails.env.production?
require 'rspec/rails'
require 'webmock/rspec'

# This driver is stateless: it has no database, and every persistence step - the
# DID document, the log, and the CMSM session - happens in a remote OYDID
# repository over HTTP. That is precisely what a spec run must never reach, or
# the suite would write into production. WebMock turns any unstubbed request
# into a failure instead of a silent network call.
WebMock.disable_net_connect!(allow_localhost: false)

RSpec.configure do |config|
  config.infer_spec_type_from_file_location!
  config.filter_rails_from_backtrace!
end
