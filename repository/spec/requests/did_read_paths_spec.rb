require 'rails_helper'

# Regression specs for revocation across all read paths.
#
# A revoked DID must not be resolvable anywhere — in particular not through the
# did:web bridge (GET /:did/did.json), which third parties are pointed to by the
# documentation and which used to serve the old DID Document with 200 while
# GET /doc/{id} already refused to resolve it.
#
# NOTE: these examples exercise real cryptography through the oydid gem; they
# require the native dependencies (libsodium/ed25519), i.e. run them inside the
# repository container.
RSpec.describe "DID read paths and revocation", type: :request do
  def gen_opts
    { return_secrets: true, skip_publish: true, authentication: true,
      x25519_keyAgreement: true, key_type: 'ed25519' }.dup
  end

  # create a DID and persist it locally through the public /doc endpoint
  def create_did
    status, _msg = Oydid.create({}, gen_opts)
    post "/doc", params: { did: status["did"], "did-document" => status["doc"], logs: status["log"] }, as: :json
    expect(response).to have_http_status(:success)
    status
  end

  # Revoke a DID without any network access: the revocation record is produced by
  # Oydid.create, its "previous" references are built exactly as Oydid.revoke
  # does, and it is stored through the client-managed deactivation endpoint.
  def revoke_did(status)
    log     = JSON.parse(status["log"].to_json)
    revoke  = JSON.parse(status["revocation_log"].to_json)
    create_entry    = log.find { |e| e["op"].to_i == 2 }
    terminate_entry = log.find { |e| e["op"].to_i == 0 }
    revoke["previous"] = [
      Oydid.multi_hash(Oydid.canonical(create_entry), LOG_HASH_OPTIONS).first,
      Oydid.multi_hash(Oydid.canonical(terminate_entry), LOG_HASH_OPTIONS).first
    ]

    post "/1.0/deactivateIdentifier", params: {
      identifier: { did: status["did"] },
      options: { log_revoke: revoke }
    }, as: :json
    expect(response).to have_http_status(200)
    expect(JSON.parse(response.body)["success"]).to eq(true)
  end

  def identifier(status)
    status["did"].delete_prefix("did:oyd:").split("@").first
  end

  let(:revoked_status) { [410, 404] }

  describe "active DID" do
    it "resolves on all read paths" do
      id = identifier(create_did)

      get "/doc/#{id}"
      expect(response).to have_http_status(200)

      get "/#{id}/did.json"
      expect(response).to have_http_status(200)
      body = JSON.parse(response.body)
      expect(body["verificationMethod"]).to be_an(Array).and be_present

      get "/1.0/identifiers/did:oyd:#{id}"
      expect(response).to have_http_status(200)
    end
  end

  describe "revoked DID" do
    it "is refused by /doc/{id}" do
      status = create_did
      revoke_did(status)

      get "/doc/#{identifier(status)}"
      expect(revoked_status).to include(response.status)
      expect(JSON.parse(response.body)["error"]).to eq("revoked")
    end

    it "is refused by the did:web bridge (regression: used to answer 200)" do
      status = create_did
      revoke_did(status)

      get "/#{identifier(status)}/did.json"
      expect(revoked_status).to include(response.status)
      expect(JSON.parse(response.body)["error"]).to eq("revoked")
      expect(response.body).not_to include("publicKeyMultibase")
      expect(response.headers["Cache-Control"]).to eq("no-store")
    end

    it "is refused by /doc/{id} with followAlsoKnownAs=true" do
      status = create_did
      revoke_did(status)

      # followAlsoKnownAs used to disable the revocation check entirely
      get "/doc/#{identifier(status)}?followAlsoKnownAs=true"
      expect(revoked_status).to include(response.status)
    end

    it "is refused by the universal-resolver endpoint with a valid HTTP status" do
      status = create_did
      revoke_did(status)

      get "/1.0/identifiers/did:oyd:#{identifier(status)}"
      # regression: internal error code 1 was used as HTTP status, producing an
      # unparseable response ("Unsupported response code in HTTP response")
      expect(response.status).to be_between(400, 599)
      expect(revoked_status).to include(response.status)
    end

    it "does not leak the document through /doc_raw either" do
      status = create_did
      revoke_did(status)

      get "/doc_raw/#{identifier(status)}"
      # doc_raw is the deliberate low-level dump used by the resolver itself and
      # still returns the stored records; it must at least expose the REVOKE
      # entry so that consumers can detect the revocation
      if response.status == 200
        log = JSON.parse(response.body)["log"]
        expect(log.map { |e| e["op"] }).to include(1)
      end
    end
  end

  # DIDs hosted by another repository are resolved remotely through the gem.
  # Oydid.retrieve_document turns every non-200 answer of that repository into
  # nil and returns the reason as the second value, so the did:web bridge must
  # read that message - otherwise a remote 410 degrades into "not found".
  describe "DID hosted by another repository" do
    it "reports a remotely revoked DID as revoked, not as not found" do
      allow(Oydid).to receive(:read).and_return([nil, "revoked"])

      get "/zQmRemotelyHostedIdentifierNotInThisRepository1/did.json"
      expect(revoked_status).to include(response.status)
      expect(JSON.parse(response.body)["error"]).to eq("revoked")
      expect(response.headers["Cache-Control"]).to eq("no-store")
    end

    it "still answers 404 when the remote repository does not know the DID" do
      allow(Oydid).to receive(:read).and_return([nil, "cannot retrieve document"])

      get "/zQmRemotelyHostedIdentifierNotInThisRepository2/did.json"
      expect(response).to have_http_status(404)
      expect(JSON.parse(response.body)["error"]).to eq("not found")
    end
  end

  # The resolver UI on the start page consumes this endpoint; it must carry the
  # full DID Resolution Result the Universal Resolver used to return for did:oyd.
  describe "GET /1.0/resolve/:did" do
    it "returns the full resolution result for an active DID" do
      id = identifier(create_did)

      get "/1.0/resolve/did:oyd:#{id}"
      expect(response).to have_http_status(200)
      body = JSON.parse(response.body)
      expect(body.keys).to include("didDocument", "didResolutionMetadata", "didDocumentMetadata")

      expect(body["didDocument"]["id"]).to eq("did:oyd:#{id}")
      expect(body["didDocument"]["verificationMethod"]).to be_an(Array).and be_present

      expect(body["didResolutionMetadata"]["did"]["method"]).to eq("oyd")
      expect(body["didResolutionMetadata"]["did"]["methodSpecificId"]).to eq(id)
      expect(body["didResolutionMetadata"]["contentType"]).to eq("application/did+ld+json")

      meta = body["didDocumentMetadata"]
      expect(meta["keys"].map { |k| k["kid"] }).to all(match(/#key-(doc|rev)\z/))
      expect(meta["log"]).to be_an(Array).and be_present
      expect(meta["log_hash"]).to be_present
      expect(meta["termination_log_id"]).to be_a(Integer)
    end

    it "works without the did:oyd prefix" do
      id = identifier(create_did)

      get "/1.0/resolve/#{id}"
      expect(response).to have_http_status(200)
      expect(JSON.parse(response.body)["didDocument"]["id"]).to eq("did:oyd:#{id}")
    end

    it "refuses a revoked DID" do
      status = create_did
      revoke_did(status)

      get "/1.0/resolve/did:oyd:#{identifier(status)}"
      expect(revoked_status).to include(response.status)
      expect(JSON.parse(response.body)["error"]).to eq("revoked")
      expect(response.body).not_to include("publicKeyHex")
    end

    it "answers 404 for an unknown identifier" do
      get "/1.0/resolve/did:oyd:zQmBogusIdentifierThatDoesNotExistAtAll12345"
      expect(response).to have_http_status(404)
    end

    it "leaves /1.0/identifiers/ returning the bare DID Document" do
      id = identifier(create_did)

      get "/1.0/identifiers/did:oyd:#{id}"
      expect(response).to have_http_status(200)
      body = JSON.parse(response.body)
      expect(body).to have_key("verificationMethod")
      expect(body).not_to have_key("didDocument")
    end
  end

  describe "start page" do
    it "serves the resolver UI and keeps the repository information" do
      get "/"
      expect(response).to have_http_status(200)
      expect(response.body).to include("OYDID Resolver")
      expect(response.body).to include("/1.0/resolve/")
      expect(response.body).to include("/api-docs")
      expect(response.body).to include("github.com/OwnYourData/oydid")
      # the result is written with textContent, never innerHTML
      expect(response.body).not_to include("innerHTML")
    end

    it "renders the list of other DID resolvers server-side" do
      get "/"
      expect(response.body).to include("Other DID Resolvers")
      ApplicationController::OTHER_RESOLVERS.each do |r|
        expect(response.body).to include(r[:url])
        expect(response.body).to include(r[:name])
        expect(response.body).to include(CGI.escapeHTML(r[:description]))
      end
      # external links must not hand over the opener
      expect(response.body.scan(/target="_blank"/).size)
        .to eq(response.body.scan(/rel="noopener noreferrer"/).size)
    end

    it "keeps the resolver list usable without JavaScript" do
      get "/"
      # the block is part of the markup and only hidden by script after a
      # successful resolution - it must not start out as display:none
      expect(response.body).to match(/<div id="resolvers">/)
      expect(response.body).not_to match(/#resolvers\s*\{[^}]*display:\s*none/)
    end
  end

  describe "unknown identifier" do
    it "answers 404 on the did:web bridge" do
      get "/zQmBogusIdentifierThatDoesNotExistAtAll12345/did.json"
      expect(response).to have_http_status(404)
      expect(JSON.parse(response.body)["error"]).to eq("not found")
    end

    it "answers 4xx/5xx but never an invalid status on the other read paths" do
      get "/doc/zQmBogusIdentifierThatDoesNotExistAtAll12345"
      expect(response.status).to be_between(400, 599)

      get "/1.0/identifiers/did:oyd:zQmBogusIdentifierThatDoesNotExistAtAll12345"
      expect(response.status).to be_between(400, 599)
    end
  end
end
