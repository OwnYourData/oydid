# Keeps the suite off the public internet.
#
# Seven examples used to resolve DID documents and logs over HTTP against
# oydid.ownyourdata.eu and did2.data-container.net. That made the suite depend
# on production staying reachable and on data from 2022 never changing - a CI
# failure then said nothing about the code.
#
# The recorded responses live in spec/fixtures/http; manifest.json maps each URL
# to its status, content type and body file. To refresh one, fetch the URL and
# overwrite the body file - the expectations under spec/output must then be
# checked, not blindly regenerated.
#
# disable_net_connect! makes any unstubbed request fail loudly, so a newly added
# network call cannot slip in unnoticed.

require "json"
require "webmock/rspec"

WebMock.disable_net_connect!(allow_localhost: false)

module HttpFixtures
  DIR = File.expand_path("../fixtures/http", __dir__)

  def self.entries
    @entries ||= JSON.parse(File.read(File.join(DIR, "manifest.json")))
  end

  def self.body(entry)
    File.read(File.join(DIR, entry["body"]))
  end
end

RSpec.configure do |config|
  config.before(:each) do
    HttpFixtures.entries.each do |entry|
      stub_request(:get, entry["url"]).to_return(
        status: entry["status"],
        body: HttpFixtures.body(entry),
        headers: { "Content-Type" => entry["content_type"] },
      )
    end
  end
end
