module ResolveHelper
    def resolve_did(did, options)
        if did.to_s == ""
            return nil
        end
        if did.include?(LOCATION_PREFIX)
            tmp = did.split(LOCATION_PREFIX)
            did = tmp[0]
            did_location = tmp[1]
        end
        
        # setup
        currentDID = {
            "did": did,
            "doc": "",
            "log": [],
            "doc_log_id": nil,
            "termination_log_id": nil,
            "last_id": nil,
            "last_sign_id": nil,
            "error": 0,
            "message": ""
        }.transform_keys(&:to_s)
        did_hash = did.delete_prefix("did:oyd:")
        did10 = did_hash[0,10]

        # get did location
        did_location = ""
        if !options[:doc_location].nil?
            did_location = options[:doc_location]
        end
        if did_location.to_s == ""
            if !options[:location].nil?
                did_location = options[:location]
            end
        end

        # retrieve DID document
        did_document = retrieve_document(did_hash, did10 +  ".doc", did_location, options)
        currentDID["doc"] = did_document

        # retrieve log
        log_array = Log.where(did: did).pluck(:item)
        currentDID["log"] = log_array

        # traverse log to get current DID state
        dag = dag_did(log_array)
        currentDID = dag_update(dag.vertices.first, log_array, currentDID)

        return currentDID
    end
end