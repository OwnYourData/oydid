require 'rails_helper'

# CMSM for update and deactivate. Both went through this driver without a CMSM
# branch at all, and a client-held revocation record was answered with 500
# without ever revoking anything.
#
# Only the decisions this controller makes are exercised here: a full update
# flow would need a published DID and therefore a real repository. The gem's
# own suite covers the cryptography.
RSpec.describe "CMSM lifecycle endpoints", type: :request do
  let(:repository) { Oydid::DEFAULT_LOCATION }
  let(:sessions) { {} }

  def as_json(body, status = 200)
    { status: status, body: body.to_json, headers: { 'Content-Type' => 'application/json' } }
  end

  before do
    stub_request(:get, %r{\A#{Regexp.escape(repository)}/cmsm/}).to_return do |request|
      stored = sessions[request.uri.path.split('/').last]
      stored.nil? ? as_json({ error: "unknown or expired CMSM session" }, 404) : as_json(stored)
    end
  end

  describe "POST /1.0/updateIdentifier (CMSM)" do
    it "requires the revocation record of the current document when starting a flow" do
      priv = Oydid.generate_private_key("", "p256-priv", {}).first
      pub  = Oydid.public_key(priv, {}).first

      post "/1.0/updateIdentifier", params: {
        args: { did: "did:oyd:zQmSomeExistingDid" },
        didDocument: { "hello" => "world" },
        options: { cmsm: true, key_type: 'Secp256r1' },
        key_hex: Oydid.key_to_hex(pub).first
      }, as: :json

      expect(response).to have_http_status(400), response.body
      expect(JSON.parse(response.body)["error"])
        .to eq("CMSM update requires the revocation record of the current document (log_revoke_old)")
    end

    it "requires a public key when starting a flow" do
      post "/1.0/updateIdentifier", params: {
        args: { did: "did:oyd:zQmSomeExistingDid" },
        didDocument: { "hello" => "world" },
        options: { cmsm: true, key_type: 'Secp256r1' }
      }, as: :json

      expect(response).to have_http_status(400), response.body
      expect(JSON.parse(response.body)["error"]).to eq("missing public key in CMSM")
    end

    it "takes the DID under update from the session instead of the request" do
      sessions["cmsm-known"] = { "did_old" => "zQmSomeExistingDid" }

      post "/1.0/updateIdentifier", params: {
        args: {},
        options: { cmsm: true, session: "cmsm-known", sig: "zSig" }
      }, as: :json

      # the flow is resolved and handed to the gem; what matters here is that it
      # is no longer rejected as "missing DID" before that happens
      expect(JSON.parse(response.body)["error"]).not_to eq("missing DID")
    end

    it "reports an unknown session as a client error" do
      post "/1.0/updateIdentifier", params: {
        args: {},
        options: { cmsm: true, session: "cmsm-does-not-exist", sig: "zSig" }
      }, as: :json

      expect(response).to have_http_status(400), response.body
      expect(JSON.parse(response.body)["error"]).to eq("unknown or expired CMSM session")
    end
  end

  describe "POST /1.0/deactivateIdentifier" do
    it "hands a client-held revocation record to the gem instead of answering 500" do
      allow(Oydid).to receive(:revoke).and_return([{ "doc" => "zQmRevoked" }, ""])

      post "/1.0/deactivateIdentifier", params: {
        identifier: { did: "did:oyd:zQmSomeExistingDid" },
        options: { log_revoke: { "doc" => "zQmRevoked", "sig" => "zSig" } }
      }, as: :json

      expect(response).to have_http_status(200), response.body
      body = JSON.parse(response.body)
      expect(body["success"]).to eq(true)
      expect(body["did"]).to eq("did:oyd:zQmSomeExistingDid")
      expect(Oydid).to have_received(:revoke)
    end

    it "reports a rejected revocation record as a client error" do
      allow(Oydid).to receive(:revoke)
        .and_return([nil, "log_revoke does not match the current document"])

      post "/1.0/deactivateIdentifier", params: {
        identifier: { did: "did:oyd:zQmSomeExistingDid" },
        options: { log_revoke: { "doc" => "zQmWrong" } }
      }, as: :json

      expect(response).to have_http_status(400), response.body
      expect(JSON.parse(response.body)["error"]).to eq("log_revoke does not match the current document")
    end
  end
end
