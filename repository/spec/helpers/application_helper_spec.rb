require 'rails_helper'

# Unit test for the shared persistence helper used by both DidsController#create
# and ProvidersController. Uses the real oydid gem for hashing (no signatures).
RSpec.describe ApplicationHelper, type: :helper do
  describe "#local_store_did" do
    let(:did)         { "did:oyd:zABCDEF1234@https://example.com" }
    let(:did_hash)    { "zABCDEF1234" }
    let(:did_document) do
      { "doc" => { "hello" => "world" }, "key" => "zDocPub:zRevPub", "log" => "zTermRef" }
    end
    let(:create_log)    { { "ts" => 1, "op" => 2, "doc" => "zCreateRef", "sig" => "sigC", "previous" => [] } }
    let(:terminate_log) { { "ts" => 1, "op" => 0, "doc" => "zRevRef",    "sig" => "sigT", "previous" => [] } }
    let(:terminate_hash) do
      Oydid.multi_hash(Oydid.canonical(terminate_log.slice("ts", "op", "doc", "sig", "previous")), LOG_HASH_OPTIONS).first
    end
    # encrypted-revocation-log update entry (no "op" key) referencing the TERMINATE record
    let(:revocation_update) { { "value" => "ENC", "nonce" => "N", "log" => terminate_hash } }

    subject(:store!) do
      helper.local_store_did(did, did_document, [create_log, terminate_log, revocation_update])
    end

    it "stores the DID under the bare hash (prefix and location stripped)" do
      store!
      record = Did.find_by_did(did_hash)
      expect(record).not_to be_nil
      expect(record.public_key).to eq("zDocPub")
      expect(JSON.parse(record.doc)).to eq(did_document)
    end

    it "stores the op log entries (CREATE + TERMINATE) but not the update entry as its own record" do
      store!
      expect(Log.where(did: did_hash).count).to eq(2)
      ops = Log.where(did: did_hash).map { |l| JSON.parse(l.item)["op"] }
      expect(ops).to contain_exactly(0, 2)
    end

    it "attaches the encrypted-revocation-log to the matching TERMINATE record" do
      store!
      term = Log.find_by_oyd_hash(terminate_hash)
      expect(term).not_to be_nil
      expect(JSON.parse(term.item)["encrypted-revocation-log"]).to eq("value" => "ENC", "nonce" => "N")
    end

    it "is idempotent (no duplicate rows on repeated calls)" do
      store!
      store!
      expect(Did.where(did: did_hash).count).to eq(1)
      expect(Log.where(did: did_hash).count).to eq(2)
    end

    it "returns [true, ''] on success" do
      expect(store!).to eq([true, ""])
    end

    it "returns an error for an unparseable document" do
      ok, msg = helper.local_store_did(did, "not-json", [])
      expect(ok).to eq(false)
      expect(msg).to be_present
    end
  end
end
