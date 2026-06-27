require 'rails_helper'

# LocalCmsmStore is the adapter the oydid gem uses (via options[:cmsm_store]) to
# read/write CMSM intermediate data in the local database. No crypto involved.
RSpec.describe LocalCmsmStore do
  let(:store) { described_class.new }
  let(:pubkey) { "zClientPublicKey" }
  let(:payload) do
    {
      revocationKey: "zRevPriv",
      did_doc: { "authentication" => ["#key-doc"] },
      did_key: "zDocPub:zRevPub",
      l2_doc: "zL2DocHash",
      r1: { "op" => 1 }
    }
  end

  it "returns nil for an unknown public key" do
    expect(store.get("does-not-exist")).to be_nil
  end

  it "persists a payload and reads it back as a Hash" do
    store.set(pubkey, payload)
    got = store.get(pubkey)

    expect(got).to be_a(Hash)
    expect(got["revocationKey"]).to eq("zRevPriv")
    expect(got["did_key"]).to eq("zDocPub:zRevPub")
    expect(got["did_doc"]).to eq({ "authentication" => ["#key-doc"] })
  end

  it "stores exactly one row per public key (upsert)" do
    store.set(pubkey, payload)
    store.set(pubkey, payload.merge(l2_doc: "zUpdated"))

    expect(Cmsm.where(pubkey: pubkey).count).to eq(1)
    expect(store.get(pubkey)["l2_doc"]).to eq("zUpdated")
  end

  it "matches the string-keyed shape generate_base expects" do
    store.set(pubkey, payload)
    got = store.get(pubkey).transform_keys(&:to_s)
    expect(got.keys).to include("revocationKey", "did_doc", "did_key", "l2_doc", "r1")
  end
end
