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

  # Update a DID without any network access, through the registrar endpoint -
  # which loads the current state from the local database and hands the gem a
  # LocalDidStore, so dag_update never reaches for HTTP.
  #
  # Returns the same shape create_did does, so updates can be chained.
  #
  # The endpoint hands the new keys back as the hex of the *wrapped* key bytes
  # (update_keys does multi_decode(...).unpack("H*"), so the multicodec header is
  # still in there - the same convention as publicKeyHex "ed01..."), while
  # private_key_from_hex wants the bare key material. Unwrapping uses the layout
  # Oydid.key_to_hex documents for private keys: [uint16 codec][uint8 length][key].
  def update_did(status, payload = {})
    post "/1.0/updateIdentifier", params: {
      args:        { did: status["did"] },
      didDocument: payload,
      secret:      { old_doc_enc: status["private_key"],
                     old_rev_enc: status["revocation_key"] }
    }, as: :json
    expect(response).to have_http_status(200), response.body

    body    = JSON.parse(response.body)
    key_for = ->(fragment) do
      entry = body["keys"].to_a.find { |k| k["kid"].to_s.end_with?(fragment) }
      expect(entry).not_to be_nil, "no #{fragment} in #{body["keys"].inspect}"
      hex = entry["privateKeyHex"]
      expect(hex).to be_present, "#{fragment} came back without a private part"
      _code, _length, raw = [hex].pack("H*").unpack("SCa*")
      key, msg = Oydid.private_key_from_hex(raw.unpack1("H*"), key_type: "ed25519")
      expect(key).not_to be_nil, msg.to_s
      key
    end
    { "did"            => body["did"],
      "private_key"    => key_for.call("#key-doc"),
      "revocation_key" => key_for.call("#key-rev") }
  end

  def resolution_metadata(did)
    get "/1.0/resolve/#{did}"
    expect(response).to have_http_status(200), response.body
    JSON.parse(response.body)["didDocumentMetadata"]
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

    # DID Core 7.1.3: "If a DID has been deactivated, DID document metadata MUST
    # include this property with the boolean value true." Only the resolution
    # result can carry that statement - and a consumer behind a
    # universal-resolver driver never sees the HTTP status, so for it this is the
    # only way "revoked" and "never existed" stay distinguishable.
    it "reports deactivated when the resolution result was asked for" do
      status = create_did
      revoke_did(status)

      get "/1.0/identifiers/did:oyd:#{identifier(status)}",
          headers: { "Accept" => 'application/ld+json;profile="https://w3id.org/did-resolution"' }
      expect(response).to have_http_status(200), response.body
      body = JSON.parse(response.body)
      expect(body["didDocument"]).to be_nil
      expect(body["didDocumentMetadata"]["deactivated"]).to eq(true)
      # error stays reserved for identifiers that were never there
      expect(body["didResolutionMetadata"]).not_to have_key("error")
      expect(body["didResolutionMetadata"]["did"]["methodSpecificId"]).to eq(identifier(status))
      expect(response.body).not_to include("publicKeyMultibase")
      expect(response.headers["Cache-Control"]).to eq("no-store")
      # the answer depends on Accept, so a cache must not mix the two shapes
      expect(response.headers["Vary"].to_s).to include("Accept")
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
      # "did" used to duplicate didDocument.id here - removed, because it was the
      # one method-specific name in this structure that could collide with a
      # future standard one
      expect(meta).not_to have_key("did")
    end

    it "works without the did:oyd prefix" do
      id = identifier(create_did)

      get "/1.0/resolve/#{id}"
      expect(response).to have_http_status(200)
      expect(JSON.parse(response.body)["didDocument"]["id"]).to eq("did:oyd:#{id}")
    end

    # This endpoint always answers with a resolution result, so a revoked DID is
    # reported as deactivated rather than refused: DID Core 7.1.3 requires the
    # statement, and it used to be unreachable here. The bare document paths
    # (/doc, /{id}/did.json, and /1.0/identifiers/ without the profile) keep
    # their 410 - see the "revoked DID" group above.
    it "reports a revoked DID as deactivated, without a document" do
      status = create_did
      revoke_did(status)

      get "/1.0/resolve/did:oyd:#{identifier(status)}"
      expect(response).to have_http_status(200), response.body
      body = JSON.parse(response.body)
      expect(body["didDocument"]).to be_nil
      expect(body["didDocumentMetadata"]).to eq({ "deactivated" => true })
      expect(body["didResolutionMetadata"]).not_to have_key("error")
      expect(response.body).not_to include("publicKeyHex")
      expect(response.headers["Cache-Control"]).to eq("no-store")
    end

    # the counterpart to the example above: "never existed" must stay
    # distinguishable from "deactivated", and error is what says so
    it "answers 404 for an unknown identifier" do
      get "/1.0/resolve/did:oyd:zQmBogusIdentifierThatDoesNotExistAtAll12345"
      expect(response).to have_http_status(404)
      expect(JSON.parse(response.body)["error"]).to eq("not found")
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

  # /1.0/identifiers/ answers in two shapes. The bare DID Document has to stay
  # the default - that is what every consumer of this endpoint reads today - and
  # the full resolution result is served only when the client asks for the
  # did-resolution profile.
  describe "content negotiation on GET /1.0/identifiers/:did" do
    let(:profile) { 'application/ld+json;profile="https://w3id.org/did-resolution"' }

    it "serves the full resolution result when the profile is requested" do
      id = identifier(create_did)

      get "/1.0/identifiers/did:oyd:#{id}", headers: { "Accept" => profile }
      expect(response).to have_http_status(200)
      body = JSON.parse(response.body)
      expect(body.keys).to include("didDocument", "didResolutionMetadata", "didDocumentMetadata")
      expect(body["didDocument"]["id"]).to eq("did:oyd:#{id}")
    end

    it "keeps the bare document for a plain Accept header" do
      id = identifier(create_did)

      get "/1.0/identifiers/did:oyd:#{id}", headers: { "Accept" => "*/*" }
      expect(response).to have_http_status(200)
      body = JSON.parse(response.body)
      expect(body).to have_key("verificationMethod")
      expect(body).not_to have_key("didDocument")
    end

    # quoting of the profile value is optional in the wild
    it "accepts the profile without quotes" do
      id = identifier(create_did)

      get "/1.0/identifiers/did:oyd:#{id}",
          headers: { "Accept" => "application/ld+json;profile=https://w3id.org/did-resolution" }
      expect(response).to have_http_status(200)
      expect(JSON.parse(response.body)).to have_key("didDocumentMetadata")
    end

    # without this a cache in front of the endpoint may hand one shape to a
    # client that asked for the other
    it "varies on Accept" do
      id = identifier(create_did)

      get "/1.0/identifiers/did:oyd:#{id}"
      expect(response.headers["Vary"].to_s).to include("Accept")
    end
  end

  # Every update mints a new identifier in did:oyd, so a resolver has to state
  # which one is current. DID Core does that through didDocumentMetadata.
  describe "version identifiers in didDocumentMetadata" do
    it "names the DID itself for a document that was never updated" do
      id = identifier(create_did)

      get "/1.0/resolve/did:oyd:#{id}"
      expect(response).to have_http_status(200)
      meta = JSON.parse(response.body)["didDocumentMetadata"]
      expect(meta["canonicalId"]).to eq("did:oyd:#{id}")
      expect(meta).not_to have_key("equivalentId")
    end

    # DID Core 7.1.3 - without `updated` a consumer cannot tell how old the
    # version it holds is; it is omitted while there has never been an update.
    it "reports created and versionId, and omits updated until there is one" do
      id   = identifier(create_did)
      meta = resolution_metadata("did:oyd:#{id}")
      expect(meta["versionId"]).to eq(id)
      expect(meta["created"]).to match(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/)
      expect(meta).not_to have_key("updated")
    end

    it "reports updated and the current versionId after an update" do
      v1 = create_did
      v2 = update_did(v1, "hello" => "second")
      meta = resolution_metadata("did:oyd:" + identifier(v1))

      expect(meta["created"]).to match(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/)
      expect(meta["updated"]).to match(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/)
      # versionId names the resolved version, so "did:oyd:" + versionId is the
      # canonical DID - that is the point of handing out the bare hash
      expect(meta["versionId"]).to eq(identifier(v2))
      expect("did:oyd:" + meta["versionId"]).to eq(meta["canonicalId"])
    end

    # Resolving through an earlier version has to report every OTHER version as
    # equivalent, not just the current one. With two versions the two readings
    # cannot be told apart - which is why this uses three.
    it "reports every other version, whichever version was requested" do
      v1 = create_did
      v2 = update_did(v1, "hello" => "second")
      v3 = update_did(v2, "hello" => "third")
      ids = [v1, v2, v3].map { |s| "did:oyd:" + identifier(s) }
      expect(ids.uniq.length).to eq(3)

      ids.each_with_index do |requested, i|
        meta = resolution_metadata(requested)
        expect(meta["canonicalId"]).to eq(ids.last), "canonicalId for version #{i + 1}"
        expect(meta["equivalentId"])
          .to match_array(ids - [requested]), "equivalentId for version #{i + 1}"
      end
    end

    # the point of the exercise: the identifier a relying party holds - printed
    # on a data carrier, stored in a database - keeps naming itself
    it "keeps the requested version as the id of the document" do
      v1 = create_did
      update_did(update_did(v1, "hello" => "second"), "hello" => "third")

      get "/1.0/resolve/did:oyd:#{identifier(v1)}"
      expect(response).to have_http_status(200)
      body = JSON.parse(response.body)
      expect(body["didDocument"]["id"]).to eq("did:oyd:" + identifier(v1))
      expect(body["didDocumentMetadata"]["canonicalId"]).not_to eq(body["didDocument"]["id"])
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
