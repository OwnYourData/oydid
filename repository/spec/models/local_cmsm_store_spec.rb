require 'rails_helper'

# LocalCmsmStore is the adapter the oydid gem uses (via options[:cmsm_store]) to
# read/write CMSM intermediate data in the local database. No crypto involved.
#
# Records are addressed by the session handle the gem generates - not by the
# public key, which may legitimately be reused across flows.
RSpec.describe LocalCmsmStore do
  let(:store)   { described_class.new }
  let(:session) { "cmsm-0123456789abcdef" }
  let(:payload) do
    {
      publicKey: "zDocPub",
      pubRevoKey: "zRevPub",
      revocationKey: nil,
      did_doc: { "authentication" => ["#key-doc"] },
      ts: 1787306400,
      doc_location: nil,
      sig_rev: "zSigRev",
      sig_doc: nil,
      sig_create: nil
    }
  end

  it "returns nil for an unknown session" do
    expect(store.get("does-not-exist")).to be_nil
  end

  it "persists a payload and reads it back as a Hash" do
    store.set(session, payload)
    got = store.get(session)

    expect(got).to be_a(Hash)
    expect(got["publicKey"]).to eq("zDocPub")
    expect(got["pubRevoKey"]).to eq("zRevPub")
    expect(got["sig_rev"]).to eq("zSigRev")
    expect(got["ts"]).to eq(1787306400)
    expect(got["did_doc"]).to eq({ "authentication" => ["#key-doc"] })
  end

  it "stores exactly one row per session (upsert across phases)" do
    store.set(session, payload)
    store.set(session, payload.merge(sig_doc: "zSigDoc"))

    expect(Cmsm.where(session: session).count).to eq(1)
    expect(store.get(session)["sig_doc"]).to eq("zSigDoc")
  end

  it "keeps flows for the same public key apart" do
    store.set("cmsm-first",  payload)
    store.set("cmsm-second", payload)

    expect(Cmsm.count).to eq(2)
    expect(Cmsm.where(pubkey: "zDocPub").count).to eq(2)
  end

  it "records the public key for lookups, without making it the identifier" do
    store.set(session, payload)
    expect(Cmsm.find_by_session(session).pubkey).to eq("zDocPub")
  end

  it "treats a session older than the TTL as gone and removes it" do
    store.set(session, payload)
    Cmsm.find_by_session(session).update_column(:created_at, (Cmsm::TTL + 1.minute).ago)

    expect(store.get(session)).to be_nil
    expect(Cmsm.find_by_session(session)).to be_nil
  end

  it "drops a finished flow on delete" do
    store.set(session, payload)
    store.delete(session)

    expect(store.get(session)).to be_nil
    expect(Cmsm.where(session: session).count).to eq(0)
  end

  it "matches the string-keyed shape generate_base expects" do
    store.set(session, payload)
    got = store.get(session).transform_keys(&:to_s)
    expect(got.keys).to include("publicKey", "pubRevoKey", "revocationKey",
                                "did_doc", "ts", "doc_location",
                                "sig_rev", "sig_doc", "sig_create")
  end
end
