module ApplicationHelper
    def resolve_did(did, options)
        if did.to_s == ""
            return nil
        end
        if did.include?(LOCATION_PREFIX)
            tmp = did.split(LOCATION_PREFIX)
            did = tmp[0]
            # did_location = tmp[1]
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
            "message": "",
            "verification": ""
        }.transform_keys(&:to_s)
        did_hash = did.delete_prefix("did:oyd:")

        # get did location
        did_location = ""
        if !options[:doc_location].nil?
            did_location = options[:doc_location]
        end

        # retrieve DID document
        did_document = local_retrieve_document(did_hash)
        if did_document.nil?
            currentDID["error"] = 404
            currentDID["message"] = "did not found"
            return currentDID
        end
        currentDID["doc"] = did_document

        # retrieve log
        did_hash = did_hash.split("@").first
        log_array = local_retrieve_log(did_hash)
        currentDID["log"] = log_array

        # traverse log to get current DID state
        dag, create_index, terminate_index, msg = Oydid.dag_did(log_array, options)
        if dag.nil?
            currentDID["error"] = 1
            currentDID["message"] = msg
            return currentDID
        end

        ordered_log_array = Oydid.dag2array(dag, log_array, create_index, [], options)
        ordered_log_array << log_array[terminate_index]
        currentDID["log"] = ordered_log_array
        currentDID = dag_update(currentDID, options)
        return currentDID
    end

    def dag_update(currentDID, options)
        i = 0
        initial_did = currentDID["did"].to_s
        initial_did = initial_did.delete_prefix("did:oyd:")
        initial_did = initial_did.split("@").first
        current_public_doc_key = ""
        verification_output = false
        currentDID["log"].each do |el|
            case el["op"]
            when 2,3 # CREATE, UPDATE
                doc_did = el["doc"]
                doc_location = Oydid.get_location(doc_did)
                did_hash = doc_did.delete_prefix("did:oyd:")
                did_hash = did_hash.split("@").first
                did10 = did_hash[0,10]
                doc = local_retrieve_document(did_hash)
                if doc.nil?
                    currentDID["error"] = 2
                    msg = "cannot retrieve " + doc_did.to_s
                    currentDID["message"] = msg
                    return currentDID
                end
                if el["op"] == 2 # CREATE
                    if !Oydid.match_log_did?(el, doc)
                        currentDID["error"] = 1
                        currentDID["message"] = "Signatures in log don't match"
                        return currentDID
                    end
                end
                currentDID["did"] = doc_did
                currentDID["doc"] = doc
                if did_hash == initial_did
                    verification_output = true
                end
                if verification_output
                    currentDID["verification"] += "identifier: " + did_hash.to_s + "\n"
                    currentDID["verification"] += "✅ is hash of DID Document:" + "\n"
                    currentDID["verification"] += JSON.pretty_generate(doc) + "\n"
                    currentDID["verification"] += "(Details: https://ownyourdata.github.io/oydid/#calculate_hash)" + "\n\n"
                end
                current_public_doc_key = currentDID["doc"]["key"].split(":").first rescue ""
            when 0 # TERMINATE
                currentDID["termination_log_id"] = i

                doc_did = currentDID["did"]
                doc_location = Oydid.get_location(doc_did)
                did_hash = doc_did.delete_prefix("did:oyd:")
                did_hash = did_hash.split("@").first
                did10 = did_hash[0,10]
                doc = local_retrieve_document(did_hash)
                term = doc["log"]
                log_location = term.split("@")[1] rescue ""
                if log_location.to_s == ""
                    log_location = DEFAULT_LOCATION
                end
                term = term.split("@").first
                if Oydid.hash(Oydid.canonical(el)) != term
                    currentDID["error"] = 1
                    currentDID["message"] = "Log reference and record don't match"
                    if verification_output
                        currentDID["verification"] += "'log' reference in DID Document: " + term.to_s + "\n"
                        currentDID["verification"] += "⛔ does not match TERMINATE log record:" + "\n"
                        currentDID["verification"] += JSON.pretty_generate(el) + "\n"
                        currentDID["verification"] += "(Details: https://ownyourdata.github.io/oydid/#calculate_hash)" + "\n\n"
                    end
                    return currentDID
                end
                if verification_output
                    currentDID["verification"] += "'log' reference in DID Document: " + term.to_s + "\n"
                    currentDID["verification"] += "✅ is hash of TERMINATE log record:" + "\n"
                    currentDID["verification"] += JSON.pretty_generate(el) + "\n"
                    currentDID["verification"] += "(Details: https://ownyourdata.github.io/oydid/#calculate_hash)" + "\n\n"
                end

                # check if there is a revocation entry
                revocation_record = {}
                revoc_term = el["doc"]
                revoc_term = revoc_term.split("@").first
                revoc_term_found = false
                log_array = local_retrieve_log(did_hash)
                log_array.each do |log_el|
                    log_el_structure = log_el.dup
                    if log_el["op"].to_i == 1 # TERMINATE
                        log_el_structure.delete("previous")
                    end
                    if Oydid.hash(Oydid.canonical(log_el_structure)) == revoc_term
                        revoc_term_found = true
                        revocation_record = log_el.dup
                        if verification_output
                            currentDID["verification"] += "'doc' reference in TERMINATE log record: " + revoc_term.to_s + "\n"
                            currentDID["verification"] += "✅ is hash of REVOCATION log record (without 'previous' attribute):" + "\n"
                            currentDID["verification"] += JSON.pretty_generate(log_el) + "\n"
                            currentDID["verification"] += "(Details: https://ownyourdata.github.io/oydid/#calculate_hash)" + "\n\n"
                        end
                        break
                    end
                end unless log_array.nil?

                if revoc_term_found
                    update_term_found = false
                    log_array.each do |log_el|
                        if log_el["op"] == 3
                            if log_el["previous"].include?(Oydid.hash(Oydid.canonical(revocation_record)))
                                update_term_found = true
                                message = log_el["doc"].to_s

                                signature = log_el["sig"]
                                public_key = current_public_doc_key.to_s
                                signature_verification = Oydid.verify(message, signature, public_key).first
                                if signature_verification
                                    if verification_output
                                        currentDID["verification"] += "found UPDATE log record:" + "\n"
                                        currentDID["verification"] += JSON.pretty_generate(log_el) + "\n"
                                        currentDID["verification"] += "✅ public key from last DID Document: " + current_public_doc_key.to_s + "\n"
                                        currentDID["verification"] += "verifies 'doc' reference of new DID Document: " + log_el["doc"].to_s + "\n"
                                        currentDID["verification"] += log_el["sig"].to_s + "\n"
                                        currentDID["verification"] += "of next DID Document (Details: https://ownyourdata.github.io/oydid/#verify_signature)" + "\n"

                                        next_doc_did = log_el["doc"].to_s
                                        next_doc_location = Oydid.get_location(next_doc_did)
                                        next_did_hash = next_doc_did.delete_prefix("did:oyd:")
                                        next_did_hash = next_did_hash.split("@").first
                                        next_did10 = next_did_hash[0,10]
                                        next_doc = local_retrieve_document(next_did_hash)
                                        if next_doc.nil?
                                            currentDID["error"] = 2
                                            currentDID["message"] = "cannot retrieve " + next_doc_did.to_s
                                            return currentDID
                                        end
                                        if public_key == next_doc["key"].split(":").first
                                            currentDID["verification"] += "⚠️  no key rotation in updated DID Document" + "\n"
                                        end
                                        currentDID["verification"] += "\n"
                                    end
                                else
                                    currentDID["error"] = 1
                                    currentDID["message"] = "Signature does not match"
                                    if verification_output
                                        new_doc_did = log_el["doc"].to_s
                                        new_doc_location = Oydid.get_location(new_doc_did)
                                        new_did_hash = new_doc_did.delete_prefix("did:oyd:")
                                        new_did_hash = new_did_hash.split("@").first
                                        new_did10 = new_did_hash[0,10]
                                        new_doc = local_retrieve_document(new_did_hash)
                                        currentDID["verification"] += "found UPDATE log record:" + "\n"
                                        currentDID["verification"] += JSON.pretty_generate(log_el) + "\n"
                                        currentDID["verification"] += "⛔ public key from last DID Document: " + current_public_doc_key.to_s + "\n"
                                        currentDID["verification"] += "does not verify 'doc' reference of new DID Document: " + log_el["doc"].to_s + "\n"
                                        currentDID["verification"] += log_el["sig"].to_s + "\n"
                                        currentDID["verification"] += "next DID Document (Details: https://ownyourdata.github.io/oydid/#verify_signature)" + "\n"
                                        currentDID["verification"] += JSON.pretty_generate(new_doc) + "\n\n"
                                    end
                                    return currentDID
                                end
                                break
                            end
                        end
                    end

                else
                    if verification_output
                        currentDID["verification"] += "Revocation reference in log record: " + revoc_term.to_s + "\n"
                        currentDID["verification"] += "✅ cannot find revocation record searching at" + "\n"
                        currentDID["verification"] += "- " + log_location + "\n"
                        if !options.transform_keys(&:to_s)["log_location"].nil?
                            currentDID["verification"] += "- " + options.transform_keys(&:to_s)["log_location"].to_s + "\n"
                        end
                        currentDID["verification"] += "(Details: https://ownyourdata.github.io/oydid/#retrieve_log)" + "\n\n"
                    end
                    break
                end
            when 1 # revocation log entry
                # do nothing
            else
                currentDID["error"] = 2
                currentDID["message"] = "FATAL ERROR: op code '" + el["op"].to_s + "' not implemented"
                return currentDID

            end
            i += 1
        end unless currentDID["log"].nil?

        return currentDID
    end

    def local_retrieve_document(doc_hash)
        doc = nil
        @did = Did.find_by_did(doc_hash)
        if @did.nil?
            return nil
        else
            doc = JSON.parse(@did.doc) rescue nil
            return doc
        end
    end

    def local_retrieve_log(didHash)
        logs = Log.where(did: didHash).pluck(:item).map { |i| JSON.parse(i) } rescue []

        # identify if TERMINATE entry has already revocation record
        logs = add_next(logs)
        # add all log entries that came before (use previous)
        logs = add_previous(logs, [didHash])

        return logs
    end

    def add_next(logs)
        new_entries = []
        logs.each do |log|
            if log["op"] == 0 # TERMINATE
                @log = Log.find_by_oyd_hash(remove_location(log["doc"]))
                if !@log.nil?
                    tmp = Log.where(did: @log.did).pluck(:item).map { |i| JSON.parse(i) } rescue []
                    tmp.delete(log)
                    new_entries << tmp
                    new_entries << add_next(tmp)
                end
            end
        end
        [new_entries, logs].compact.flatten.uniq
    end

    def add_previous(logs, done)
        new_dids = []
        new_entries = []
        logs.each do |log|
            if log["previous"] != []
                log["previous"].each do |entry|
                    @log = Log.find_by_oyd_hash(entry)
                    if !@log.nil?
                        if !done.include?(@log.did)
                            new_dids << @log.did
                        end
                    end
                end
            end
        end
        if new_dids.count > 0
            new_dids = new_dids.uniq
            new_entries = Log.where(did: new_dids).pluck(:item).map { |i| JSON.parse(i) } rescue []
            more_entries = add_previous(new_entries, [new_dids, done].flatten.uniq)
        end
        [new_entries, more_entries, logs].compact.flatten.uniq
    end

    def remove_location(id)
        location = id.split(LOCATION_PREFIX)[1] rescue ""
        id = id.split(LOCATION_PREFIX)[0] rescue id
        id.delete_prefix("did:oyd:")

    end
end
