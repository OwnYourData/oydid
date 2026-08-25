# == Schema Information
#
# Table name: dids
#
#  id         :integer          not null, primary key
#  did        :string
#  doc        :text
#  public_key :string
#  alias      :string
#  created_at :datetime         not null
#  updated_at :datetime         not null
#
# Indexes
#
#  index_dids_on_did         (did) UNIQUE
#  index_dids_on_public_key  (public_key)
#
class Did < ApplicationRecord

    # Is this version of the DID revoked?
    #
    # The document names the hash of its own TERMINATE entry in "log"; that
    # entry names the sub-entry-hash of the revocation record in "doc". The DID
    # is revoked exactly when that record has been submitted.
    def revoked?
        terminate = Log.find_by_any_hash(Did.strip_location(JSON.parse(doc)["log"])) rescue nil
        return false if terminate.nil?
        record = JSON.parse(terminate.item)["doc"] rescue nil
        return false if record.nil?
        Log.find_by_any_hash(Did.strip_location(record)).present?
    end

    # Resolve the "did:oyd:{public-key}" shorthand.
    #
    # A public key regularly carries more than one row: key rotation on UPDATE
    # is optional, so a non-rotating update leaves the old (revoked) version and
    # the new one side by side. `find_by_public_key` is LIMIT 1 without ORDER BY
    # and can hand back either - which after a VACUUM can even change without
    # the data changing. Answer with the newest version that is still active;
    # for the intended case (one DID plus its update history) that is exactly
    # the current document.
    #
    # When every version is revoked, return the newest one anyway: the caller
    # verifies the log and reports the revocation, which is more useful than
    # "not found".
    #
    # Fetch the ids first and load one row at a time: a single collector key
    # carries thousands of rows, and pulling every `doc` into memory to answer
    # one lookup is a cost with no benefit. The common case - newest version
    # active - ends after the first row.
    def self.find_by_public_key_active(public_key)
        return nil if public_key.to_s == ""
        ids = where(public_key: public_key).order(id: :desc).pluck(:id)
        return nil if ids.empty?
        ids.each do |id|
            candidate = find_by(id: id)
            return candidate if candidate && !candidate.revoked?
        end
        find_by(id: ids.first)
    end

    # Guardrail: at any time a public key controls at most one active DID.
    # Reusing a key after the DID it controlled has been revoked stays allowed.
    def self.key_in_active_use?(public_key)
        candidate = find_by_public_key_active(public_key)
        !candidate.nil? && !candidate.revoked?
    end

    def self.strip_location(value)
        value.to_s.split(LOCATION_PREFIX).first
             .split(CGI.escape(LOCATION_PREFIX)).first
             .delete_prefix("did:oyd:")
    rescue StandardError
        value.to_s
    end
end
