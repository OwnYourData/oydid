require 'rails_helper'

# A REVOKE log entry is referenced from two directions and therefore carries two
# hashes (see ruby-gem/lib/oydid/log.rb):
#
#   entry-hash      over {ts,op,doc,sig,previous}  <- used by previous chains
#   sub-entry-hash  over {ts,op,doc,sig}           <- named in the TERMINATE doc
#
# Both write paths - POST /log/:did and local_store_did - must agree on which is
# which, otherwise a revocation submitted through one of them is filed under a
# hash the other side never looks for. That is what these examples pin down.
#
# NOTE: these examples exercise real cryptography through the oydid gem; they
# require the native dependencies (libsodium/ed25519).
RSpec.describe "revocation log hashes", type: :request do
  def gen_opts
    { return_secrets: true, skip_publish: true, authentication: true,
      x25519_keyAgreement: true, key_type: 'ed25519' }.dup
  end

  def create_did
    status, _msg = Oydid.create({}, gen_opts)
    post "/doc", params: { did: status["did"], "did-document" => status["doc"],
                           logs: status["log"] }, as: :json
    expect(response).to have_http_status(:success)
    status
  end

  def identifier(status)
    status["did"].delete_prefix("did:oyd:").split("@").first
  end

  # the revocation record as Oydid.revoke builds it, without network access
  def revocation_record(status)
    log    = JSON.parse(status["log"].to_json)
    revoke = JSON.parse(status["revocation_log"].to_json)
    revoke["previous"] = [
      Oydid.multi_hash(Oydid.canonical(log.find { |e| e["op"].to_i == 2 }),
                       LOG_HASH_OPTIONS).first,
      Oydid.multi_hash(Oydid.canonical(log.find { |e| e["op"].to_i == 0 }),
                       LOG_HASH_OPTIONS).first
    ]
    revoke
  end

  def both_hashes(record)
    [Oydid.multi_hash(Oydid.canonical(record.slice("ts", "op", "doc", "sig", "previous")),
                      LOG_HASH_OPTIONS).first,
     Oydid.multi_hash(Oydid.canonical(record.slice("ts", "op", "doc", "sig")),
                      LOG_HASH_OPTIONS).first]
  end

  it "are distinct, and the TERMINATE entry names the sub-entry-hash" do
    status = create_did
    entry, sub = both_hashes(revocation_record(status))

    expect(entry).not_to eq(sub)

    terminate = JSON.parse(status["log"].to_json).find { |e| e["op"].to_i == 0 }
    expect(terminate["doc"]).to eq(sub)
  end

  it "are both stored when the record arrives through POST /log/:did" do
    status = create_did
    record = revocation_record(status)
    entry, sub = both_hashes(record)

    post "/log/#{identifier(status)}", params: { log: record }, as: :json
    expect(response).to have_http_status(200)

    log = Log.find_by(oyd_hash: entry)
    expect(log).to be_present
    expect(log.sub_hash).to eq(sub)
    expect(Log.find_by_any_hash(sub)).to eq(log)
    expect(Log.find_by_any_hash(entry)).to eq(log)
  end

  it "are both stored when the record arrives through the deactivation endpoint" do
    status = create_did
    record = revocation_record(status)
    entry, sub = both_hashes(record)

    post "/1.0/deactivateIdentifier", params: {
      identifier: { did: status["did"] }, options: { log_revoke: record }
    }, as: :json
    expect(response).to have_http_status(200)

    log = Log.find_by(oyd_hash: entry)
    expect(log).to be_present
    expect(log.sub_hash).to eq(sub)
  end

  it "do not lead to the same record being stored twice" do
    status = create_did
    record = revocation_record(status)
    _entry, sub = both_hashes(record)

    2.times do
      post "/log/#{identifier(status)}", params: { log: record }, as: :json
      expect(response).to have_http_status(200)
    end

    expect(Log.where(sub_hash: sub).count).to eq(1)
  end

  it "let the read path see a revocation submitted through POST /log/:did" do
    status = create_did

    get "/doc/#{identifier(status)}"
    expect(response).to have_http_status(200)

    post "/log/#{identifier(status)}", params: { log: revocation_record(status) }, as: :json
    expect(response).to have_http_status(200)

    get "/doc/#{identifier(status)}"
    expect([410, 404]).to include(response.status)
  end
end
