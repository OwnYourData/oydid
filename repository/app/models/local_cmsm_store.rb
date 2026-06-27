# Adapter that lets the oydid gem read and write the intermediate data of the
# Client-Managed-Secret-Mode (CMSM) flow in the local database (Cmsm model)
# instead of posting it to a remote location.
#
# The gem calls #get(pubkey) (in check_cmsm) and #set(pubkey, payload)
# (in persist_cmsm) when it receives this object via options[:cmsm_store].
class LocalCmsmStore
    # returns the persisted payload as a Hash, or nil if nothing is stored
    def get(pubkey)
        rec = Cmsm.find_by_pubkey(pubkey)
        return nil if rec.nil?
        JSON.parse(rec.payload) rescue nil
    end

    # persists the payload (Hash) for the given public key
    def set(pubkey, payload)
        rec = Cmsm.find_by_pubkey(pubkey) || Cmsm.new
        rec.pubkey = pubkey
        rec.payload = payload.to_json
        rec.save
        [true, ""]
    end
end
