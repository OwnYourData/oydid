require 'rails_helper'

# Resolving the "did:oyd:{public-key}" shorthand.
#
# A public key regularly carries more than one row: key rotation on UPDATE is
# optional, so a non-rotating update leaves the old (revoked) version next to
# the new one. The lookup has to answer with the current document, and it has to
# do so deterministically - find_by_public_key was LIMIT 1 without ORDER BY.
#
# The log entries here are synthetic: revoked? only follows hashes and reads
# fields, so no real cryptography is needed to pin the selection down.
RSpec.describe Did, type: :model do
  let(:key) { "z6MkTestKeyForSelectionOnly" }

  def version(name, revoked:, key: "z6MkTestKeyForSelectionOnly")
    terminate = "hashT-#{name}"
    record    = "hashR-#{name}"
    Log.create!(did: name, oyd_hash: terminate, ts: 0,
                item: { "op" => 0, "doc" => record }.to_json)
    if revoked
      Log.create!(did: name, oyd_hash: record, ts: 0,
                  item: { "op" => 1, "doc" => "sub-#{name}" }.to_json)
    end
    Did.create!(did: name, public_key: key,
                doc: { "log" => terminate, "key" => key }.to_json)
  end

  describe ".find_by_public_key_active" do
    it "returns nil for an unknown key" do
      expect(Did.find_by_public_key_active("z6MkNothingHere")).to be_nil
    end

    it "returns nil for a blank key" do
      version("solo", revoked: false)
      expect(Did.find_by_public_key_active("")).to be_nil
      expect(Did.find_by_public_key_active(nil)).to be_nil
    end

    it "returns the only version there is" do
      only = version("solo", revoked: false)
      expect(Did.find_by_public_key_active(key)).to eq(only)
    end

    it "returns the newest version when none is revoked" do
      version("older", revoked: false)
      newer = version("newer", revoked: false)
      expect(Did.find_by_public_key_active(key)).to eq(newer)
    end

    it "skips a revoked newer version in favour of an active older one" do
      active = version("active", revoked: false)
      version("revoked", revoked: true)
      expect(Did.find_by_public_key_active(key)).to eq(active)
    end

    it "returns the newest version when every version is revoked" do
      version("first",  revoked: true)
      last = version("second", revoked: true)
      expect(Did.find_by_public_key_active(key)).to eq(last)
    end

    it "does not mix up two different keys" do
      mine = version("mine", revoked: false)
      version("other", revoked: false, key: "z6MkSomeOtherKey")
      expect(Did.find_by_public_key_active(key)).to eq(mine)
    end
  end

  describe "#revoked?" do
    it "is false while no revocation record has been submitted" do
      expect(version("open", revoked: false)).not_to be_revoked
    end

    it "is true once the record the TERMINATE entry names exists" do
      expect(version("closed", revoked: true)).to be_revoked
    end

    it "is false when the document carries no usable log reference" do
      did = Did.create!(did: "nolog", public_key: key, doc: { "key" => key }.to_json)
      expect(did).not_to be_revoked
    end
  end
end
