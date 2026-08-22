# Intermediate data of a Client-Managed-Secret-Mode flow, held between the
# phases of a single create/update/deactivate operation.
#
# These records are short-lived on purpose. Until the flow completes they hold
# material that authorises operations on the DID being built, so they expire
# after TTL and are deleted as soon as the flow finishes (see
# ProvidersController#create).
class Cmsm < ApplicationRecord
    TTL = 15.minutes

    scope :expired, -> { where(created_at: ...TTL.ago) }

    def expired?
        created_at.nil? || created_at < TTL.ago
    end

    # remove flows that were started but never completed
    def self.sweep
        expired.delete_all
    end
end
