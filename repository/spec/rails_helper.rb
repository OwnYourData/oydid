require 'spec_helper'
ENV['RAILS_ENV'] ||= 'test'
require_relative '../config/environment'

abort("The Rails environment is running in production mode!") if Rails.env.production?
require 'rspec/rails'

# Load the schema into the (sqlite) test database on demand. The repository
# tracks db/schema.rb, so this keeps the test DB in sync without requiring a
# separate migration run.
begin
  ActiveRecord::Migration.maintain_test_schema!
rescue ActiveRecord::PendingMigrationError, ActiveRecord::NoDatabaseError
  ActiveRecord::Schema.verbose = false
  load Rails.root.join('db', 'schema.rb')
end

RSpec.configure do |config|
  config.use_transactional_fixtures = true
  config.infer_spec_type_from_file_location!
  config.filter_rails_from_backtrace!
end
