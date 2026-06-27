require 'rails_helper'

# Request specs for the local DID Provider endpoints. These drive the real
# oydid gem (signatures, hashing) and the local database.
#
# NOTE: the happy-path create/update/deactivate examples exercise real
# cryptography; they require the oydid native dependencies (libsodium/ed25519),
# i.e. run them inside the repository container or an environment where the
# gem loads.
RSpec.describe "DID Provider endpoints", type: :request do
  # options used to generate a self-managed ed25519 DID via the gem
  def gen_opts
    { return_secrets: true, skip_publish: true, authentication: true,
      x25519_keyAgreement: true, key_type: 'ed25519' }.dup
  end

  # create a DID with the gem and persist it through the public /doc endpoint
  # (DidsController#create) so the providers endpoints have something to act on
  def seed_did
    status, _msg = Oydid.create({}, gen_opts)
    post "/doc", params: { did: status["did"], "did-document" => status["doc"], logs: status["log"] }, as: :json
    expect(response).to have_http_status(:success)
    status
  end

  describe "POST /1.0/createIdentifier (standard)" do
    it "creates and locally stores an ed25519 DID" do
      expect {
        post "/1.0/createIdentifier", params: { options: {} }, as: :json
      }.to change { Did.count }.by(1)

      expect(response).to have_http_status(200)
      body = JSON.parse(response.body)
      expect(body["did"]).to match(/\Adid:oyd:/)
      expect(body["controllerKeyId"]).to end_with("#key-doc")
      expect(body["keys"]).to be_an(Array).and be_present
      # the created DID is resolvable from the local database
      did_hash = body["did"].delete_prefix("did:oyd:")
      expect(Did.find_by_did(did_hash)).not_to be_nil
    end
  end

  describe "POST /1.0/createIdentifier (CMSM)" do
    it "runs the two-phase client-managed-secret-mode flow" do
      # client key pair (private key stays on the client)
      client_priv = Oydid.generate_private_key("", "ed25519-priv", {}).first
      client_pub  = Oydid.public_key(client_priv, {}).first
      key_hex     = Oydid.multi_decode(client_pub).first.unpack1('H*')[4..] # strip "ed01" multicodec prefix

      # phase 1: register the public key, receive the value to sign
      expect {
        post "/1.0/createIdentifier",
             params: { options: { cmsm: true, key_type: 'ed25519' }, key_hex: key_hex },
             as: :json
      }.to change { Cmsm.count }.by(1)
      expect(response).to have_http_status(201)
      phase1 = JSON.parse(response.body)
      expect(phase1["cmsm"]).to eq(true)
      expect(phase1["sign"]).to be_present

      # client signs the returned value with its private document key
      sig = Oydid.sign(phase1["sign"], client_priv, {}).first

      # phase 2: submit the signature, DID gets created and stored locally
      expect {
        post "/1.0/createIdentifier",
             params: { options: { cmsm: true, key_type: 'ed25519', sig: sig }, key_hex: key_hex },
             as: :json
      }.to change { Did.count }.by(1)
      expect(response).to have_http_status(200)
      body = JSON.parse(response.body)
      expect(body["did"]).to match(/\Adid:oyd:/)
    end
  end

  describe "POST /1.0/updateIdentifier" do
    it "returns 404 for an unknown DID" do
      post "/1.0/updateIdentifier", params: { args: { did: "did:oyd:zUnknown" } }, as: :json
      expect(response).to have_http_status(404)
    end

    it "rejects a client-managed update with an invalid log signature" do
      status = seed_did
      bad_doc = { "doc" => {}, "key" => status["doc"]["key"], "log" => "x" }
      post "/1.0/updateIdentifier", params: {
        args: { did: status["did"] },
        didDocument: bad_doc,
        options: {
          log_revoke:    { "op" => 1, "doc" => "a", "sig" => "bad" },
          log_update:    { "op" => 3, "doc" => "b", "sig" => "invalid-signature" },
          log_terminate: { "op" => 0, "doc" => "c", "sig" => "bad" }
        }
      }, as: :json
      expect(response).to have_http_status(400)
    end

    it "updates a self-managed DID and stores the new state" do
      status = seed_did
      post "/1.0/updateIdentifier", params: {
        args: { did: status["did"] },
        secret: { old_doc_enc: status["private_key"], old_rev_enc: status["revocation_key"] }
      }, as: :json

      expect(response).to have_http_status(200)
      body = JSON.parse(response.body)
      expect(body["did"]).to match(/\Adid:oyd:/)
      expect(body["keys"]).to be_present
    end
  end

  describe "POST /1.0/deactivateIdentifier" do
    it "returns 404 for an unknown DID" do
      post "/1.0/deactivateIdentifier", params: { identifier: { did: "did:oyd:zUnknown" } }, as: :json
      expect(response).to have_http_status(404)
    end

    it "stores a client-supplied revocation log (client-managed deactivation)" do
      status   = seed_did
      did_hash = status["did"].delete_prefix("did:oyd:")
      revoke   = { "ts" => Time.now.utc.to_i, "op" => 1, "doc" => "zRevDoc", "sig" => "zSig", "previous" => [] }

      expect {
        post "/1.0/deactivateIdentifier", params: {
          identifier: { did: status["did"] },
          options: { log_revoke: revoke }
        }, as: :json
      }.to change { Log.where(did: did_hash).where("item LIKE ?", '%"op":1%').count }.by(1)

      expect(response).to have_http_status(200)
      expect(JSON.parse(response.body)["success"]).to eq(true)
    end

    it "revokes a self-managed DID via the gem" do
      status = seed_did
      post "/1.0/deactivateIdentifier", params: {
        identifier: { did: status["did"] },
        secret: {
          doc_enc:     status["private_key"],
          rev_enc:     status["revocation_key"],
          old_doc_enc: status["private_key"],
          old_rev_enc: status["revocation_key"]
        }
      }, as: :json

      expect(response).to have_http_status(200)
      expect(JSON.parse(response.body)["success"]).to eq(true)
    end
  end
end
