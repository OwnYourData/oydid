module ApplicationHelper
    def resolve_did(did, options)
        if did.to_s == ""
            return nil
        end
        if did.include?(LOCATION_PREFIX)
            tmp = did.split(LOCATION_PREFIX)
            did = tmp[0]
        end
        if did.include?(CGI.escape LOCATION_PREFIX)
            tmp = did.split(CGI.escape LOCATION_PREFIX)
            did = tmp[0] 
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
        did_identifier = did.delete_prefix("did:oyd:")

        # get did location
        did_location = ""
        if !options[:doc_location].nil?
            did_location = options[:doc_location]
        end

        # retrieve DID document
        did, did_document = local_retrieve_document(did_identifier)
        if did_document.nil?
            currentDID["error"] = 404
            currentDID["message"] = "did not found"
            return currentDID
        end
        currentDID["doc"] = did_document

        # retrieve log
        # did_identifier = did_identifier.split(LOCATION_PREFIX).first
        # did_identifier = did_identifier.split(CGI.escape(LOCATION_PREFIX)).first
        log_array = local_retrieve_log(did)
        currentDID["log"] = log_array

        # traverse log to get current DID state
        dag, create_index, terminate_index, msg = Oydid.dag_did(log_array, options)
        if dag.nil?
            currentDID["error"] = 1
            currentDID["message"] = msg
            return currentDID
        end

        result = Oydid.dag2array(dag, log_array, create_index, [], options)
        ordered_log_array = Oydid.dag2array_terminate(dag, log_array, terminate_index, result, options)
        currentDID["log"] = ordered_log_array.flatten.uniq.compact.dup
        # !!! ugly hack
        currentDID["full_log"] = log_array
        currentDID = dag_update(currentDID, options)
        return currentDID
    end

    def dag_update(currentDID, options)
        i = 0
        initial_did = currentDID["did"].to_s
        initial_did = initial_did.delete_prefix("did:oyd:")
        initial_did = initial_did.split(LOCATION_PREFIX).first
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
                did, doc = local_retrieve_document(did_hash)
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
                did, doc = local_retrieve_document(did_hash)
                term = doc["log"]
                log_location = term.split("@")[1] rescue ""
                if log_location.to_s == ""
                    log_location = DEFAULT_LOCATION
                end
                term = term.split(LOCATION_PREFIX).first.split(CGI.escape LOCATION_PREFIX).first
                log_options = options.dup
                log_options[:digest] = Oydid.get_digest(term).first
                log_options[:encode] = Oydid.get_encoding(term).first
                if Oydid.multi_hash(Oydid.canonical(el), log_options).first != term
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
                    if Oydid.multi_hash(Oydid.canonical(log_el_structure), log_options).first == revoc_term
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
                            if log_el["previous"].include?(Oydid.multi_hash(Oydid.canonical(revocation_record), options).first)
                                update_term_found = true
                                message = log_el["doc"].to_s
                                signature = log_el["sig"]
                                # public_key = current_public_doc_key.to_s
                                extend_currentDID = currentDID.dup
                                extend_currentDID["log"] = extend_currentDID["full_log"]
                                # !!!TODO: check for delegates only at certain point in time
                                pubKeys, msg = Oydid.getDelegatedPubKeysFromFullDidDocument(extend_currentDID, "doc")
                                signature_verification = false
                                used_pubkey = ""
                                pubKeys.each do |key|
                                    if Oydid.verify(message, signature, key).first
                                        signature_verification = true
                                        used_pubkey = key
                                        break
                                    end
                                end
                                if signature_verification
                                    if verification_output
                                        currentDID["verification"] += "found UPDATE log record:" + "\n"
                                        currentDID["verification"] += JSON.pretty_generate(log_el) + "\n"
                                        currentDID["verification"] += "✅ public key: " + used_pubkey.to_s + "\n"
                                        currentDID["verification"] += "verifies 'doc' reference of new DID Document: " + log_el["doc"].to_s + "\n"
                                        currentDID["verification"] += log_el["sig"].to_s + "\n"
                                        currentDID["verification"] += "of next DID Document (Details: https://ownyourdata.github.io/oydid/#verify_signature)" + "\n"

                                        next_doc_did = log_el["doc"].to_s
                                        next_doc_location = Oydid.get_location(next_doc_did)
                                        next_did_hash = next_doc_did.delete_prefix("did:oyd:")
                                        next_did_hash = next_did_hash.split("@").first
                                        next_did10 = next_did_hash[0,10]
                                        nexd_did, next_doc = local_retrieve_document(next_did_hash)
                                        if next_doc.nil?
                                            currentDID["error"] = 2
                                            currentDID["message"] = "cannot retrieve " + next_doc_did.to_s
                                            return currentDID
                                        end
                                        if pubKeys.include?(next_doc["key"].split(":").first)
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
                                        currentDID["verification"] += "⛔ none of available public keys (" + pubKeys.join(", ") + ")\n"
                                        currentDID["verification"] += "verify 'doc' reference of new DID Document: " + log_el["doc"].to_s + "\n"
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
                # handle DID Rotation
                if (i == (currentDID["log"].length-1))
                    if options[:followAlsoKnownAs]
                        current_doc = currentDID["doc"]
                        if current_doc["doc"].transform_keys(&:to_s).has_key?("alsoKnownAs")
                            rotate_DID = current_doc["doc"].transform_keys(&:to_s)["alsoKnownAs"]
                            if rotate_DID.start_with?("did:")
                                rotate_DID_method = rotate_DID.split(":").take(2).join(":")
                                did_orig = currentDID["did"]
                                if !did_orig.start_with?("did:oyd:")
                                    did_orig = "did:oyd:" + did_orig
                                end
                                case rotate_DID_method
                                when "did:ebsi"
                                    public_resolver = ENV["PUBLIC_RESOLVER"] || DEFAULT_PUBLIC_RESOLVER
                                    rotate_DID_Document = HTTParty.get(public_resolver + rotate_DID)
                                    rotate_ddoc = JSON.parse(rotate_DID_Document.parsed_response)

                                    # checks
                                    # 1) is original DID revoked -> fulfilled, otherwise we would not be in this branch
                                    # 2) das new DID reference back original DID

                                    currentDID["did"] = rotate_DID
                                    currentDID["doc"]["doc"] = rotate_ddoc["didDocument"]
                                    if verification_output
                                        currentDID["verification"] += "DID rotation to: " + rotate_DID.to_s + "\n"
                                        currentDID["verification"] += "✅ original DID (" + did_orig + ") revoked and referenced in alsoKnownAs\n"
                                        currentDID["verification"] += "(Details: https://ownyourdata.github.io/oydid/#did_rotation)" + "\n\n"
                                    end
                                when "did:oyd"
                                    puts "try to resolve did:oyd with our own resolver"
                                    puts "add verification text"
                                else
                                    # do nothing: DID Rotation is not supported for this DID method yet
                                end
                            end
                        end
                    end
                end
            when 5 # DELEGATE
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

    def local_retrieve_document(doc_identifier)
        did = nil
        doc = nil
        @did = Did.find_by_did(doc_identifier)
        if @did.nil?
            @did = Did.find_by_public_key(doc_identifier)
            if !@did.nil?
                did = @did.did
                doc = JSON.parse(@did.doc) rescue nil
            end
        else
            did = doc_identifier
            doc = JSON.parse(@did.doc) rescue nil
        end
        return [did, doc]
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
                @log = Log.find_by_oyd_hash(remove_location(log["doc"])) rescue nil
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
            if !log["previous"].nil? && log["previous"] != []
                log["previous"].each do |entry|
                    @log = Log.find_by_oyd_hash(entry) rescue nil
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
        # location = id.split(LOCATION_PREFIX)[1] rescue ""
        id = id.split(LOCATION_PREFIX).first.split(CGI.escape LOCATION_PREFIX).first rescue id
        id.delete_prefix("did:oyd:")
    end
end
