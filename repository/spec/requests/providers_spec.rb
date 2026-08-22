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

  # a fresh P-256 key pair, as a secure element would hand it out
  def p256
    priv = Oydid.generate_private_key("", "p256-priv", {}).first
    [priv, Oydid.public_key(priv, {}).first]
  end

    # walk the four-phase create flow and return everything the client keeps
    def cmsm_create(doc_priv, doc_pub, rev_priv, rev_pub, payload = {})
      post "/1.0/createIdentifier", params: payload.merge(
        options: { cmsm: true, key_type: 'Secp256r1' },
        key_hex:     Oydid.key_to_hex(doc_pub).first,
        rev_key_hex: Oydid.key_to_hex(rev_pub).first
      ), as: :json
      expect(response).to have_http_status(201), response.body
      ph = JSON.parse(response.body)
      session = ph["session"]

      [[rev_priv, Oydid::LOG_HASH_OPTIONS], [doc_priv, {}], [doc_priv, {}]].each do |key, opts|
        post "/1.0/createIdentifier", params: {
          options: { cmsm: true, session: session, sig: Oydid.sign(ph["sign"], key, opts).first }
        }, as: :json
        ph = JSON.parse(response.body)
      end
      expect(response).to have_http_status(200), response.body
      ph
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
    it "runs the client-managed-secret-mode flow with a server-managed revocation key" do
      # client key pair (private key stays on the client)
      client_priv = Oydid.generate_private_key("", "ed25519-priv", {}).first
      client_pub  = Oydid.public_key(client_priv, {}).first
      key_hex     = Oydid.multi_decode(client_pub).first.unpack1('H*')[4..] # strip "ed01" multicodec prefix

      # phase 1: register the public key, receive the session and value to sign
      expect {
        post "/1.0/createIdentifier",
             params: { options: { cmsm: true, key_type: 'ed25519' }, key_hex: key_hex },
             as: :json
      }.to change { Cmsm.count }.by(1)
      expect(response).to have_http_status(201)
      phase1 = JSON.parse(response.body)
      expect(phase1["cmsm"]).to eq(true)
      expect(phase1["session"]).to be_present
      expect(phase1["sign"]).to be_present
      expect(phase1["with"]).to eq("key-doc")

      # client signs the returned value with its private document key
      sig = Oydid.sign(phase1["sign"], client_priv, {}).first

      # phase 2: submit session and signature - no public key needed any more
      post "/1.0/createIdentifier",
           params: { options: { cmsm: true, session: phase1["session"], sig: sig } },
           as: :json
      expect(response).to have_http_status(201), response.body
      phase2 = JSON.parse(response.body)
      expect(phase2["phase"]).to eq(2)
      expect(phase2["with"]).to eq("key-doc")

      # phase 3: sign the CREATE log entry
      expect {
        post "/1.0/createIdentifier",
             params: { options: { cmsm: true, session: phase1["session"],
                                  sig: Oydid.sign(phase2["sign"], client_priv, {}).first } },
             as: :json
      }.to change { Did.count }.by(1)
      expect(response).to have_http_status(200), response.body
      body = JSON.parse(response.body)
      expect(body["did"]).to match(/\Adid:oyd:/)
      # the finished flow leaves nothing behind
      expect(Cmsm.find_by_session(phase1["session"])).to be_nil
    end

    it "keeps two flows for the same public key apart" do
      client_priv = Oydid.generate_private_key("", "ed25519-priv", {}).first
      client_pub  = Oydid.public_key(client_priv, {}).first
      key_hex     = Oydid.key_to_hex(client_pub).first

      sessions = 2.times.map do
        post "/1.0/createIdentifier",
             params: { options: { cmsm: true, key_type: 'ed25519' }, key_hex: key_hex },
             as: :json
        expect(response).to have_http_status(201)
        JSON.parse(response.body)["session"]
      end

      expect(sessions.uniq.length).to eq(2)
      expect(Cmsm.count).to eq(2)
    end

    it "rejects an unknown session" do
      post "/1.0/createIdentifier",
           params: { options: { cmsm: true, session: "cmsm-does-not-exist", sig: "zSig" } },
           as: :json
      expect(response).to have_http_status(400)
      expect(JSON.parse(response.body)["error"]).to eq("unknown or expired CMSM session")
    end

    it "rejects an expired session" do
      client_priv = Oydid.generate_private_key("", "ed25519-priv", {}).first
      client_pub  = Oydid.public_key(client_priv, {}).first
      key_hex     = Oydid.key_to_hex(client_pub).first

      post "/1.0/createIdentifier",
           params: { options: { cmsm: true, key_type: 'ed25519' }, key_hex: key_hex },
           as: :json
      session = JSON.parse(response.body)["session"]
      Cmsm.find_by_session(session).update_column(:created_at, (Cmsm::TTL + 1.minute).ago)

      post "/1.0/createIdentifier",
           params: { options: { cmsm: true, session: session, sig: "zSig" } },
           as: :json
      expect(response).to have_http_status(400)
      expect(JSON.parse(response.body)["error"]).to eq("unknown or expired CMSM session")
    end

    it "runs the four-phase flow with a client-managed revocation key (P-256)" do
      # both key pairs stay with the client - this is what a secure element
      # integration looks like: the repository never sees a private key
      doc_priv = Oydid.generate_private_key("", "p256-priv", {}).first
      doc_pub  = Oydid.public_key(doc_priv, {}).first
      rev_priv = Oydid.generate_private_key("", "p256-priv", {}).first
      rev_pub  = Oydid.public_key(rev_priv, {}).first

      # phase 1: both public keys, challenge for the REVOCATION key
      post "/1.0/createIdentifier", params: {
        options: { cmsm: true, key_type: 'Secp256r1' },
        key_hex:     Oydid.key_to_hex(doc_pub).first,
        rev_key_hex: Oydid.key_to_hex(rev_pub).first
      }, as: :json
      expect(response).to have_http_status(201), response.body
      phase1 = JSON.parse(response.body)
      expect(phase1["phase"]).to eq(1)
      expect(phase1["with"]).to eq("key-rev")
      session = phase1["session"]

      # phase 2: revocation signature in, challenge for the DOCUMENT key
      phase1_sig = Oydid.sign(phase1["sign"], rev_priv, Oydid::LOG_HASH_OPTIONS).first
      post "/1.0/createIdentifier", params: {
        options: { cmsm: true, session: session, sig: phase1_sig }
      }, as: :json
      expect(response).to have_http_status(201), response.body
      phase2 = JSON.parse(response.body)
      expect(phase2["phase"]).to eq(2)
      expect(phase2["with"]).to eq("key-doc")
      expect(phase2["session"]).to eq(session)

      # phase 3: TERMINATE signature in, challenge for the CREATE log entry
      post "/1.0/createIdentifier", params: {
        options: { cmsm: true, session: session,
                   sig: Oydid.sign(phase2["sign"], doc_priv, {}).first }
      }, as: :json
      expect(response).to have_http_status(201), response.body
      phase3 = JSON.parse(response.body)
      expect(phase3["phase"]).to eq(3)
      expect(phase3["with"]).to eq("key-doc")

      # phase 4: CREATE signature in, DID gets created
      expect {
        post "/1.0/createIdentifier", params: {
          options: { cmsm: true, session: session,
                     sig: Oydid.sign(phase3["sign"], doc_priv, {}).first }
        }, as: :json
      }.to change { Did.count }.by(1)
      expect(response).to have_http_status(200), response.body
      body = JSON.parse(response.body)

      # the client-managed revocation key is the one in the DID document
      did_hash  = body["did"].delete_prefix("did:oyd:")
      stored    = JSON.parse(Did.find_by_did(did_hash).doc)
      expect(stored["key"]).to eq(doc_pub + ":" + rev_pub)

      # the CREATE log entry carries a real signature - no CMSM exception needed
      create_log = Log.where(did: did_hash).map { |l| JSON.parse(l.item) }
                      .find { |l| l["op"] == 2 }
      expect(create_log).not_to be_nil
      expect(create_log["sig"]).to be_present
      expect(Oydid.verify(create_log["doc"], create_log["sig"], doc_pub).first).to eq(true)

      # ... and therefore resolves even with the strict CREATE-signature check,
      # which DIDs from the earlier CMSM flow (sig: null) cannot satisfy
      logs = Log.where(did: did_hash).map { |l| JSON.parse(l.item) }
      resolved, _msg = Oydid.read(body["did"], { local_doc: stored,
                                                 local_log: logs,
                                                 local_store: LocalDidStore.new,
                                                 strict_create_sig: true })
      expect(resolved).not_to be_nil
      expect(resolved["error"]).to eq(0), resolved["message"].to_s

      # no private key material is handed back, and nothing is left behind
      expect(body["keys"].map { |k| k["privateKeyHex"] }.compact).to be_empty
      expect(Cmsm.find_by_session(session)).to be_nil

      # the revocation record is handed out - the client cannot rebuild it
      expect(body["log_revoke"]).to be_a(Hash)
      expect(body["log_revoke"]["op"]).to eq(1)
      expect(body["log_revoke"]["sig"]).to eq(phase1_sig)
    end

    it "reports a completed session instead of accepting a fourth signature" do
      doc_priv = Oydid.generate_private_key("", "ed25519-priv", {}).first
      doc_pub  = Oydid.public_key(doc_priv, {}).first
      rev_priv = Oydid.generate_private_key("", "ed25519-priv", {}).first
      rev_pub  = Oydid.public_key(rev_priv, {}).first

      post "/1.0/createIdentifier", params: {
        options: { cmsm: true, key_type: 'ed25519' },
        key_hex:     Oydid.key_to_hex(doc_pub).first,
        rev_key_hex: Oydid.key_to_hex(rev_pub).first
      }, as: :json
      phase1  = JSON.parse(response.body)
      session = phase1["session"]

      post "/1.0/createIdentifier", params: {
        options: { cmsm: true, session: session,
                   sig: Oydid.sign(phase1["sign"], rev_priv, Oydid::LOG_HASH_OPTIONS).first }
      }, as: :json
      expect(response).to have_http_status(201), response.body

      # the session is removed once the flow completes, so a further signature
      # can only hit an unknown session
      phase2 = JSON.parse(response.body)
      post "/1.0/createIdentifier", params: {
        options: { cmsm: true, session: session,
                   sig: Oydid.sign(phase2["sign"], doc_priv, {}).first }
      }, as: :json
      expect(response).to have_http_status(201), response.body

      phase3 = JSON.parse(response.body)
      post "/1.0/createIdentifier", params: {
        options: { cmsm: true, session: session,
                   sig: Oydid.sign(phase3["sign"], doc_priv, {}).first }
      }, as: :json
      expect(response).to have_http_status(200), response.body

      post "/1.0/createIdentifier", params: {
        options: { cmsm: true, session: session, sig: "zSig" }
      }, as: :json
      expect(response).to have_http_status(400)
      expect(JSON.parse(response.body)["error"]).to eq("unknown or expired CMSM session")
    end

    # regression: the multicodec prefix used to be hard-coded to "ed01"
    # (ed25519-pub) while the CMSM branch defaults to key_type 'p256', so a
    # P-256 public key was silently encoded as an ed25519 key
    it "encodes a P-256 public key with the p256-pub multicodec" do
      client_priv = Oydid.generate_private_key("", "p256-priv", {}).first
      client_pub  = Oydid.public_key(client_priv, {}).first
      key_hex     = Oydid.key_to_hex(client_pub).first

      expect {
        post "/1.0/createIdentifier",
             params: { options: { cmsm: true, key_type: 'Secp256r1' }, key_hex: key_hex },
             as: :json
      }.to change { Cmsm.count }.by(1)
      expect(response).to have_http_status(201)

      # the session keeps inputs only - did_key is derived from the public keys
      stored_doc_key = JSON.parse(Cmsm.last.payload)["publicKey"]
      expect(Oydid.get_keytype(stored_doc_key)).to eq('p256-pub')
      expect(stored_doc_key).to eq(client_pub)
    end

    it "rejects a public key that does not match the key type" do
      post "/1.0/createIdentifier",
           params: { options: { cmsm: true, key_type: 'Secp256r1' }, key_hex: "aa" * 32 },
           as: :json
      expect(response).to have_http_status(400)
      expect(JSON.parse(response.body)["error"]).to include("invalid public key in CMSM")
    end
  end

  describe "POST /1.0/updateIdentifier (CMSM)" do
    it "updates a DID whose keys never leave the client" do
      doc_priv = Oydid.generate_private_key("", "p256-priv", {}).first
      doc_pub  = Oydid.public_key(doc_priv, {}).first
      rev_priv = Oydid.generate_private_key("", "p256-priv", {}).first
      rev_pub  = Oydid.public_key(rev_priv, {}).first
      created  = cmsm_create(doc_priv, doc_pub, rev_priv, rev_pub, hello: "world")

      # the client rotates both keys
      doc_priv2 = Oydid.generate_private_key("", "p256-priv", {}).first
      doc_pub2  = Oydid.public_key(doc_priv2, {}).first
      rev_priv2 = Oydid.generate_private_key("", "p256-priv", {}).first
      rev_pub2  = Oydid.public_key(rev_priv2, {}).first

      # phase 1: new document, new public keys, and the revocation record of the
      # current document - no challenge needed for revoking the old document
      post "/1.0/updateIdentifier", params: {
        args:        { did: created["did"] },
        didDocument: { "hello" => "universe" },
        options:     { cmsm: true, key_type: 'Secp256r1',
                       log_revoke_old: created["log_revoke"] },
        key_hex:     Oydid.key_to_hex(doc_pub2).first,
        rev_key_hex: Oydid.key_to_hex(rev_pub2).first
      }, as: :json
      expect(response).to have_http_status(201), response.body
      ph = JSON.parse(response.body)
      session = ph["session"]
      expect(ph["with"]).to eq("key-rev")

      # the last signature is made with the OLD document key - it authorises the
      # transition, so the old key has to still exist at this point
      [[rev_priv2, Oydid::LOG_HASH_OPTIONS, "key-doc"],
       [doc_priv2, {}, "key-doc-old"],
       [doc_priv,  {}, nil]].each do |key, opts, next_with|
        post "/1.0/updateIdentifier", params: {
          options: { cmsm: true, session: session, sig: Oydid.sign(ph["sign"], key, opts).first }
        }, as: :json
        ph = JSON.parse(response.body)
        expect(ph["with"]).to eq(next_with) if next_with
      end

      expect(response).to have_http_status(200), response.body
      expect(ph["did"]).to match(/\Adid:oyd:/)
      expect(ph["did"]).not_to eq(created["did"])
      expect(ph["did_old"]).to eq(created["did"])

      # both new client keys are in the new document, no private parts returned
      new_hash = ph["did"].delete_prefix("did:oyd:")
      expect(JSON.parse(Did.find_by_did(new_hash).doc)["key"]).to eq(doc_pub2 + ":" + rev_pub2)
      expect(ph["keys"].map { |k| k["privateKeyHex"] }.compact).to be_empty
      expect(ph["log_revoke"]).to be_a(Hash)

      # the UPDATE entry is signed by the key of the document being replaced
      update_log = Log.where(did: new_hash).map { |l| JSON.parse(l.item) }
                      .find { |l| l["op"] == 3 }
      expect(update_log).not_to be_nil
      expect(Oydid.verify(update_log["doc"], update_log["sig"], doc_pub).first).to eq(true)

      expect(Cmsm.find_by_session(session)).to be_nil
    end

    it "rejects a revocation record that does not belong to the current document" do
      doc_priv = Oydid.generate_private_key("", "p256-priv", {}).first
      doc_pub  = Oydid.public_key(doc_priv, {}).first
      rev_priv = Oydid.generate_private_key("", "p256-priv", {}).first
      rev_pub  = Oydid.public_key(rev_priv, {}).first
      created  = cmsm_create(doc_priv, doc_pub, rev_priv, rev_pub, hello: "world")

      other_priv = Oydid.generate_private_key("", "p256-priv", {}).first
      other_pub  = Oydid.public_key(other_priv, {}).first
      other_rev  = Oydid.generate_private_key("", "p256-priv", {}).first
      other      = cmsm_create(other_priv, other_pub, other_rev,
                               Oydid.public_key(other_rev, {}).first, hello: "elsewhere")

      post "/1.0/updateIdentifier", params: {
        args:        { did: created["did"] },
        didDocument: { "hello" => "universe" },
        options:     { cmsm: true, key_type: 'Secp256r1',
                       log_revoke_old: other["log_revoke"] },
        key_hex:     Oydid.key_to_hex(doc_pub).first,
        rev_key_hex: Oydid.key_to_hex(rev_pub).first
      }, as: :json
      expect(response).to have_http_status(400), response.body
      expect(JSON.parse(response.body)["error"]).to include("log_revoke_old")
    end

    it "requires the revocation record at all" do
      doc_priv = Oydid.generate_private_key("", "p256-priv", {}).first
      doc_pub  = Oydid.public_key(doc_priv, {}).first
      rev_priv = Oydid.generate_private_key("", "p256-priv", {}).first
      rev_pub  = Oydid.public_key(rev_priv, {}).first
      created  = cmsm_create(doc_priv, doc_pub, rev_priv, rev_pub)

      post "/1.0/updateIdentifier", params: {
        args:        { did: created["did"] },
        didDocument: { "hello" => "universe" },
        options:     { cmsm: true, key_type: 'Secp256r1' },
        key_hex:     Oydid.key_to_hex(doc_pub).first,
        rev_key_hex: Oydid.key_to_hex(rev_pub).first
      }, as: :json
      expect(response).to have_http_status(400)
      expect(JSON.parse(response.body)["error"]).to include("log_revoke_old")
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

      expect(response).to have_http_status(200), response.body
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

    it "revokes a DID with the record the client kept (client-managed deactivation)" do
      doc_priv, doc_pub = p256
      rev_priv, rev_pub = p256
      created  = cmsm_create(doc_priv, doc_pub, rev_priv, rev_pub, hello: "world")
      did_hash = created["did"].delete_prefix("did:oyd:")

      expect {
        post "/1.0/deactivateIdentifier", params: {
          identifier: { did: created["did"] },
          options: { log_revoke: created["log_revoke"] }
        }, as: :json
      }.to change { Log.where(did: did_hash).where("item LIKE ?", '%"op":1%').count }.by(1)

      expect(response).to have_http_status(200), response.body
      expect(JSON.parse(response.body)["success"]).to eq(true)

      # the stored entry is linked into the DAG - without previous it would be
      # an orphan and the revocation would have no effect
      stored = Log.where(did: did_hash).map { |l| JSON.parse(l.item) }.select { |l| l["op"] == 1 }
      expect(stored.length).to eq(1)
      expect(stored.first["previous"]).to be_present

      # and the DID stops resolving
      doc  = JSON.parse(Did.find_by_did(did_hash).doc)
      logs = Log.where(did: did_hash).map { |l| JSON.parse(l.item) }
      resolved, _msg = Oydid.read(created["did"], { local_doc: doc, local_log: logs,
                                                    local_store: LocalDidStore.new })
      expect(resolved["error"]).not_to eq(0)
    end

    it "rejects a revocation record the DID never committed to" do
      doc_priv, doc_pub = p256
      rev_priv, rev_pub = p256
      created = cmsm_create(doc_priv, doc_pub, rev_priv, rev_pub, hello: "world")

      forged = { "ts" => Time.now.utc.to_i, "op" => 1, "doc" => "zRevDoc", "sig" => "zSig" }
      post "/1.0/deactivateIdentifier", params: {
        identifier: { did: created["did"] },
        options: { log_revoke: forged }
      }, as: :json

      expect(response).to have_http_status(400), response.body
      expect(JSON.parse(response.body)["error"]).to include("log_revoke")
    end

    it "rejects the revocation record of a different DID" do
      a_doc_priv, a_doc_pub = p256
      a_rev_priv, a_rev_pub = p256
      a = cmsm_create(a_doc_priv, a_doc_pub, a_rev_priv, a_rev_pub, hello: "a")

      b_doc_priv, b_doc_pub = p256
      b_rev_priv, b_rev_pub = p256
      b = cmsm_create(b_doc_priv, b_doc_pub, b_rev_priv, b_rev_pub, hello: "b")

      post "/1.0/deactivateIdentifier", params: {
        identifier: { did: a["did"] },
        options: { log_revoke: b["log_revoke"] }
      }, as: :json

      expect(response).to have_http_status(400), response.body
      expect(JSON.parse(response.body)["error"]).to include("log_revoke")
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

      expect(response).to have_http_status(200), response.body
      expect(JSON.parse(response.body)["success"]).to eq(true)
    end
  end
end
