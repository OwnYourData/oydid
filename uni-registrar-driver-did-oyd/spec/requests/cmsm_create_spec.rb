require 'rails_helper'

# The Client-Managed-Secret-Mode create flow, end to end through the driver.
#
# This driver keeps no state of its own: the gem persists the CMSM session in a
# repository over HTTP (POST /cmsm, GET /cmsm/:session) and publishes the
# finished DID the same way (POST /doc). All of that is answered here by an
# in-memory stand-in, so these examples exercise the real cryptography of the
# gem without touching a live host.
#
# They require the gem's native dependencies (libsodium/ed25519) to load.
RSpec.describe "POST /1.0/createIdentifier (CMSM)", type: :request do
  let(:repository) { Oydid::DEFAULT_LOCATION }
  let(:sessions) { {} }

  def as_json(body, status = 200)
    { status: status, body: body.to_json, headers: { 'Content-Type' => 'application/json' } }
  end

  # Stand-in for the CMSM session store of a repository at `host`.
  def stub_repository(host)
    stub_request(:post, "#{host}/cmsm").to_return do |request|
      envelope = JSON.parse(request.body)
      sessions["#{host}/#{envelope['session']}"] = JSON.parse(envelope["payload"])
      as_json({})
    end

    stub_request(:get, %r{\A#{Regexp.escape(host)}/cmsm/}).to_return do |request|
      stored = sessions["#{host}/#{request.uri.path.split('/').last}"]
      stored.nil? ? as_json({ error: "unknown or expired CMSM session" }, 404) : as_json(stored)
    end

    stub_request(:post, "#{host}/doc").to_return(as_json({}))
    stub_request(:post, %r{\A#{Regexp.escape(host)}/log/}).to_return(as_json({}))

    # While assembling the W3C representation the gem resolves the DID it is
    # about to publish (write -> w3c -> getDelegatedPubKeysFromDID), so this
    # read happens BEFORE the document exists. "not found" is the honest answer.
    stub_request(:get, %r{\A#{Regexp.escape(host)}/doc(_raw)?/}).to_return(as_json({ error: "not found" }, 404))
    stub_request(:get, %r{\A#{Regexp.escape(host)}/log/}).to_return(as_json([]))
  end

  before { stub_repository(repository) }

  # a fresh P-256 key pair, as a secure element would hand one out
  def p256
    priv = Oydid.generate_private_key("", "p256-priv", {}).first
    [priv, Oydid.public_key(priv, {}).first]
  end

  # phase 1: register both public keys, receive session and value to sign
  def start_flow(doc_pub, rev_pub, extra_options = {})
    post "/1.0/createIdentifier", params: {
      options: { cmsm: true, key_type: 'Secp256r1' }.merge(extra_options),
      key_hex: Oydid.key_to_hex(doc_pub).first,
      rev_key_hex: Oydid.key_to_hex(rev_pub).first
    }, as: :json
    JSON.parse(response.body)
  end

  def sign_phase(session, value, key, opts = {})
    post "/1.0/createIdentifier", params: {
      options: { cmsm: true, session: session, sig: Oydid.sign(value, key, opts).first }
    }, as: :json
    JSON.parse(response.body)
  end

  it "encodes a P-256 key with the P-256 multicodec" do
    _doc_priv, doc_pub = p256
    _rev_priv, rev_pub = p256

    phase1 = start_flow(doc_pub, rev_pub)

    expect(response).to have_http_status(201), response.body
    expect(phase1["cmsm"]).to eq(true)
    expect(phase1["phase"]).to eq(1)
    expect(phase1["session"]).to be_present
    expect(phase1["sign"]).to be_present
    expect(phase1["with"]).to eq("key-rev")
    # the challenge echoes the document key the driver decoded; a hard-coded
    # ed25519 multicodec prefix would come back as a different multibase string
    # (the revocation key is kept in the session as pubRevoKey, not in pk)
    expect(phase1["pk"]).to eq(doc_pub)
  end

  it "carries one flow through all four phases and returns a DID" do
    doc_priv, doc_pub = p256
    rev_priv, rev_pub = p256

    phase = start_flow(doc_pub, rev_pub)
    expect(response).to have_http_status(201), response.body
    session = phase["session"]

    # revocation signature, then TERMINATE, then the CREATE log entry
    [[rev_priv, Oydid::LOG_HASH_OPTIONS], [doc_priv, {}], [doc_priv, {}]].each do |key, opts|
      value = phase["sign"]
      phase = sign_phase(session, value, key, opts)
      # every intermediate phase has to stay in the same flow
      expect(phase["session"]).to eq(session) if response.status == 201
    end

    expect(response).to have_http_status(200), response.body
    expect(phase["did"]).to start_with("did:oyd:")
    expect(phase["controllerKeyId"]).to end_with("#key-doc")
  end

  it "reports an unknown session as a client error, not a server fault" do
    post "/1.0/createIdentifier", params: {
      options: { cmsm: true, session: "cmsm-does-not-exist", sig: "zSig" }
    }, as: :json

    expect(response).to have_http_status(400), response.body
    expect(JSON.parse(response.body)["error"]).to eq("unknown or expired CMSM session")
  end

  it "still requires a public key when no session is given" do
    post "/1.0/createIdentifier", params: { options: { cmsm: true } }, as: :json

    expect(response).to have_http_status(400)
    expect(JSON.parse(response.body)["error"]).to eq("missing public key in CMSM")
  end

  it "rejects a revocation key without a document key" do
    _rev_priv, rev_pub = p256

    post "/1.0/createIdentifier", params: {
      options: { cmsm: true, key_type: 'Secp256r1' },
      rev_key_hex: Oydid.key_to_hex(rev_pub).first
    }, as: :json

    expect(response).to have_http_status(400)
    expect(JSON.parse(response.body)["error"]).to eq("rev_key_hex requires key_hex in CMSM")
  end

  # The session lives in the repository the flow was started against. This
  # driver has no memory of that choice, so a client that names a location in
  # phase 1 has to keep naming it - otherwise phase 2 looks in the default
  # repository and the flow is gone.
  it "loses a flow whose location is not repeated in the next phase" do
    other = "https://did2.example"
    stub_repository(other)

    _doc_priv, doc_pub = p256
    _rev_priv, rev_pub = p256

    phase1 = start_flow(doc_pub, rev_pub, location: other)
    expect(response).to have_http_status(201), response.body
    expect(sessions.keys.first).to start_with(other)

    post "/1.0/createIdentifier", params: {
      options: { cmsm: true, session: phase1["session"], sig: "zSig" }
    }, as: :json

    expect(response).to have_http_status(400), response.body
    expect(JSON.parse(response.body)["error"]).to eq("unknown or expired CMSM session")
  end
end
