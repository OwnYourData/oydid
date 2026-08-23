require 'rails_helper'

# Guardrail: at any time a public key controls at most one active DID.
#
# The rule is deliberately narrow. It only refuses CREATE, and only while the
# DID that carries the key is still active - a non-rotating UPDATE keeps the key
# of the version it replaces and is the most common form of update, and reusing
# a key after a revocation stays allowed.
#
# NOTE: these examples exercise real cryptography through the oydid gem; they
# require the native dependencies (libsodium/ed25519).
RSpec.describe "one active DID per key", type: :request do
  def gen_opts
    { return_secrets: true, skip_publish: true, authentication: true,
      x25519_keyAgreement: true, key_type: 'ed25519' }.dup
  end

  # the same key pair for every DID in an example - that is the point here
  let(:doc_key) { Oydid.generate_private_key("", "ed25519-priv", {}).first }
  let(:rev_key) { Oydid.generate_private_key("", "ed25519-priv", {}).first }

  def build(payload)
    Oydid.create(payload, gen_opts.merge(doc_enc: doc_key, rev_enc: rev_key)).first
  end

  def publish(status)
    post "/doc", params: { did: status["did"], "did-document" => status["doc"],
                           logs: status["log"] }, as: :json
  end

  def identifier(status)
    status["did"].delete_prefix("did:oyd:").split("@").first
  end

  def revoke(status)
    log    = JSON.parse(status["log"].to_json)
    record = JSON.parse(status["revocation_log"].to_json)
    record["previous"] = [
      Oydid.multi_hash(Oydid.canonical(log.find { |e| e["op"].to_i == 2 }),
                       LOG_HASH_OPTIONS).first,
      Oydid.multi_hash(Oydid.canonical(log.find { |e| e["op"].to_i == 0 }),
                       LOG_HASH_OPTIONS).first
    ]
    post "/1.0/deactivateIdentifier", params: {
      identifier: { did: status["did"] }, options: { log_revoke: record }
    }, as: :json
  end

  it "builds distinct DIDs from the same key pair" do
    expect(identifier(build("hello" => "world")))
      .not_to eq(identifier(build("hello" => "universe")))
  end

  it "refuses a CREATE with a key an active DID already carries" do
    first = build("hello" => "world")
    publish(first)
    expect(response).to have_http_status(:success)

    second = build("hello" => "universe")
    publish(second)
    expect(response).to have_http_status(400)
    expect(JSON.parse(response.body)["error"]).to eq(KEY_IN_USE_ERROR)
    expect(Did.find_by_did(identifier(second))).to be_nil
  end

  it "accepts the key again once the DID it controlled is revoked" do
    first = build("hello" => "world")
    publish(first)
    revoke(first)
    expect(response).to have_http_status(200)

    second = build("hello" => "universe")
    publish(second)
    expect(response).to have_http_status(:success)
    expect(Did.find_by_did(identifier(second))).to be_present
  end

  it "leaves a DID with an unrelated key alone" do
    publish(build("hello" => "world"))
    other, _msg = Oydid.create({ "hello" => "elsewhere" }, gen_opts)
    publish(other)
    expect(response).to have_http_status(:success)
  end
end
