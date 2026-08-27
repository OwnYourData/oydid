require 'rails_helper'

# Request specs for the Universal Registrar driver.
#
# The driver holds no state of its own; everything it does ends up in a remote
# OYDID repository. These specs therefore cover the decisions the controller
# makes *before* it hands over to the gem - which is where the CMSM session
# handling lives.
RSpec.describe "DID Provider endpoints", type: :request do
  describe "POST /1.0/createIdentifier (CMSM)" do
    it "rejects a flow that carries neither a public key nor a session" do
      post "/1.0/createIdentifier",
           params: { options: { cmsm: true, key_type: 'p256' } },
           as: :json

      expect(response).to have_http_status(400)
      expect(JSON.parse(response.body)["error"]).to eq("missing public key in CMSM")
    end
  end

  describe "POST /1.0/createIdentifier (options)" do
    it "refuses a local location, which this driver cannot serve" do
      post "/1.0/createIdentifier",
           params: { options: { doc_location: "local" } },
           as: :json

      expect(response).to have_http_status(500)
      expect(JSON.parse(response.body)["error"]).to eq("location not supported")
    end
  end
end
