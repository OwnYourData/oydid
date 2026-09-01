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

  # Which operation created a version decides whether the one-active-DID-per-key
  # guardrail applies: op 2 is CREATE and is refused when the key is already in
  # use, op 3 is UPDATE and must always pass - a non-rotating update carries the
  # key of the version it replaces.
  describe "#document_operation" do
    let(:did) { "zQmDocumentHash" }

    def entry(op, doc)
      { "ts" => 1, "op" => op, "doc" => doc, "sig" => "z0" }
    end

    it "reports CREATE for the entry naming this DID" do
      logs = [entry(2, did), entry(0, "zQmSomethingElse")]
      expect(helper.document_operation(logs, did)).to eq(2)
    end

    it "reports UPDATE for the entry naming this DID" do
      expect(helper.document_operation([entry(3, did)], did)).to eq(3)
    end

    it "ignores the location suffix on the doc reference" do
      logs = [entry(2, "#{did}@https://oydid.ownyourdata.eu")]
      expect(helper.document_operation(logs, did)).to eq(2)
    end

    it "ignores entries that name a different DID" do
      expect(helper.document_operation([entry(2, "zQmOther")], did)).to be_nil
    end

    it "ignores TERMINATE and REVOKE entries" do
      expect(helper.document_operation([entry(0, did), entry(1, did)], did)).to be_nil
    end

    it "copes with an empty or malformed log" do
      expect(helper.document_operation([], did)).to be_nil
      expect(helper.document_operation(nil, did)).to be_nil
      expect(helper.document_operation(["nonsense", nil], did)).to be_nil
    end
  end

  # regression: add_next recursed without a cycle guard. Two DIDs whose TERMINATE
  # records point at each other's revocation record made it recurse until the
  # stack overflowed, and the endpoint answered 500 instead of resolving. Mirrors
  # the `done` set that add_previous already carries.
  describe "#local_retrieve_log with a revocation cycle" do
    before do
      Log.create!(did: "Acycle", oyd_hash: "pA", ts: 1,
                  item: { "ts" => 1, "op" => 0, "doc" => "pB", "sig" => "s", "previous" => [] }.to_json)
      Log.create!(did: "Bcycle", oyd_hash: "pB", ts: 1,
                  item: { "ts" => 1, "op" => 0, "doc" => "pA", "sig" => "s", "previous" => [] }.to_json)
    end

    it "terminates instead of overflowing the stack" do
      expect { helper.local_retrieve_log("Acycle") }.not_to raise_error
    end
  end
end
