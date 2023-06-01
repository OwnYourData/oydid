# -*- encoding: utf-8 -*-
# frozen_string_literal: true

class Oydid
    # log functions -----------------------------
    def self.add_hash(log)
        log.map do |item|
            item["entry-hash"] = multi_hash(canonical(item.slice("ts","op","doc","sig","previous")), LOG_HASH_OPTIONS).first
            if item.transform_keys(&:to_s)["op"] == 1 # REVOKE
                item["sub-entry-hash"] = multi_hash(canonical(item.slice("ts","op","doc","sig")), LOG_HASH_OPTIONS).first
            end
            item
        end
    end

    # check if signature matches current document
    # check if signature in log is correct
    def self.match_log_did?(log, doc)
        message = log["doc"].to_s
        signature = log["sig"].to_s
        public_keys = doc["key"].to_s
        public_key = public_keys.split(":")[0] rescue ""
        return verify(message, signature, public_key).first
    end

    def self.retrieve_log(did_hash, log_file, log_location, options)
        if log_location == ""
            log_location = DEFAULT_LOCATION
        end
        if !(log_location == "" || log_location == "local")
            if !log_location.start_with?("http")
                log_location = "https://" + log_location
            end
        end

        case log_location
        when /^http/
            log_location = log_location.gsub("%3A",":")
            log_location = log_location.gsub("%2F%2F","//")
            retVal = HTTParty.get(log_location + "/log/" + did_hash)
            if retVal.code != 200
                msg = retVal.parsed_response("error").to_s rescue 
                        "invalid response from " + log_location.to_s + "/log/" + did_hash.to_s

                return [nil, msg]
            end
            if options.transform_keys(&:to_s)["trace"]
                if options[:silent].nil? || !options[:silent]
                    puts "GET log for " + did_hash + " from " + log_location
                end
            end
            retVal = JSON.parse(retVal.to_s) rescue nil
            return [retVal, ""]
        when "", "local"
            doc = JSON.parse(read_private_storage(log_file)) rescue {}
            if doc == {}
                return [nil, "cannot read file '" + log_file + "'"]
            end
            return [doc, ""]
        end
    end

    def self.retrieve_log_item(log_hash, log_location, options)
        if log_location.to_s == ""
            log_location = DEFAULT_LOCATION
        end
        if !log_location.start_with?("http")
            log_location = "https://" + log_location
        end

        case log_location
        when /^http/
            log_location = log_location.gsub("%3A",":")
            log_location = log_location.gsub("%2F%2F","//")
            retVal = HTTParty.get(log_location + "/log/" + log_hash + "/item")
            if retVal.code != 200
                msg = retVal.parsed_response("error").to_s rescue 
                        "invalid response from " + log_location.to_s + "/log/" + log_hash.to_s + "/item"
                return [nil, msg]
            end
            if options.transform_keys(&:to_s)["trace"]
                if options[:silent].nil? || !options[:silent]
                    puts "GET log entry for " + log_hash + " from " + log_location
                end
            end
            retVal = JSON.parse(retVal.to_s) rescue nil
            return [retVal, ""]
        else
            return [nil, "cannot read from " + log_location]
        end
    end

    def self.dag_did(logs, options)
        dag = DAG.new
        dag_log = []
        log_hash = []

        # calculate hash values for each entry and build vertices
        i = 0
        create_entries = 0
        create_index = nil
        terminate_indices = []
        logs.each do |el|
            case el["op"].to_i
            when 0 # TERMINATE
                terminate_indices << i
            when 2 # CREATE
                create_entries += 1
                create_index = i
            end
            log_hash << Oydid.multi_hash(Oydid.canonical(el.slice("ts","op","doc","sig","previous")), LOG_HASH_OPTIONS).first
            dag_log << dag.add_vertex(id: i)
            i += 1
        end unless logs.nil?
        if create_entries != 1
            return [nil, nil, nil, "wrong number of CREATE entries (" + create_entries.to_s + ") in log" ]
        end
        if terminate_indices.length == 0
            return [nil, nil, nil, "missing TERMINATE entries" ]
        end 

        # create provisional edges between vertices
        i = 0
        logs.each do |el|
            el["previous"].each do |p|
                position = log_hash.find_index(p)
                if !position.nil?
                    dag.add_edge from: dag_log[position], to: dag_log[i]
                end
            end unless el["previous"] == []
            i += 1
        end unless logs.nil?

        # identify tangling TERMINATE entry
        i = 0
        terminate_entries = 0
        terminate_overall = 0
        terminate_index = nil
        logs.each do |el|
            if el["op"].to_i == 0
                if dag.vertices[i].successors.length == 0
                    terminate_entries += 1
                    terminate_index = i
                end
                terminate_overall += 1
            end
            i += 1
        end unless logs.nil?

        if terminate_entries != 1 && !options[:log_complete]
            if options[:silent].nil? || !options[:silent]
                return [nil, nil, nil, "cannot resolve DID" ]
            end
        end 

        # create actual edges between vertices (but only use last terminate index for delegates)
        dag = DAG.new
        dag_log = []
        log_hash = []

        # calculate hash values for each entry and build vertices
        i = 0
        create_entries = 0
        create_index = nil
        terminate_indices = []
        logs.each do |el|
            case el["op"].to_i
            when 0 # TERMINATE
                terminate_indices << i
            when 2 # CREATE
                create_entries += 1
                create_index = i
            end
            log_hash << Oydid.multi_hash(Oydid.canonical(el.slice("ts","op","doc","sig","previous")), LOG_HASH_OPTIONS).first
            dag_log << dag.add_vertex(id: i)
            i += 1
        end unless logs.nil?
        i = 0
        logs.each do |el|
            el["previous"].each do |p|
                position = log_hash.find_index(p)
                if !position.nil?
                    if logs[position]["op"].to_i == 5 # DELEGATE
                        if i == terminate_index
                            # only delegates in the last terminate index are relevant
                            dag.add_edge from: dag_log[position], to: dag_log[i]
                        end
                    else
                        dag.add_edge from: dag_log[position], to: dag_log[i]
                    end
                end
            end unless el["previous"] == []
            i += 1
        end unless logs.nil?

        return [dag, create_index, terminate_index, ""]
    end

    def self.dag2array(dag, log_array, index, result, options)
        if options.transform_keys(&:to_s)["trace"]
            if options[:silent].nil? || !options[:silent]
                puts "    vertex " + index.to_s + " at " + log_array[index]["ts"].to_s + " op: " + log_array[index]["op"].to_s + " doc: " + log_array[index]["doc"].to_s
            end
        end
        result << log_array[index]
        dag.vertices[index].successors.each do |s|
            # check if successor has predecessor that is not self (i.e. REVOKE with TERMINATE)
            s.predecessors.each do |p|
                if p[:id] != index
                    if options.transform_keys(&:to_s)["trace"]
                        if options[:silent].nil? || !options[:silent]
                            puts "    vertex " + p[:id].to_s + " at " + log_array[p[:id]]["ts"].to_s + " op: " + log_array[p[:id]]["op"].to_s + " doc: " + log_array[p[:id]]["doc"].to_s
                        end
                    end
                    result << log_array[p[:id]]
                end
            end unless s.predecessors.length < 2
            dag2array(dag, log_array, s[:id], result, options)
        end unless dag.vertices[index].successors.count == 0
        result
    end

    def self.dag2array_terminate(dag, log_array, index, result, options)
        if options.transform_keys(&:to_s)["trace"]
            if options[:silent].nil? || !options[:silent]
                puts "    vertex " + index.to_s + " at " + log_array[index]["ts"].to_s + " op: " + log_array[index]["op"].to_s + " doc: " + log_array[index]["doc"].to_s
            end
        end
        dag.vertices[index].predecessors.each do |p|
            if p[:id] != index
                if options.transform_keys(&:to_s)["trace"]
                    if options[:silent].nil? || !options[:silent]
                        puts "    vertex " + p[:id].to_s + " at " + log_array[p[:id]]["ts"].to_s + " op: " + log_array[p[:id]]["op"].to_s + " doc: " + log_array[p[:id]]["doc"].to_s
                    end
                end
                result << log_array[p[:id]]
            end
        end unless dag.vertices[index].nil?
        result << log_array[index]
        result
    end

    def self.dag_update(currentDID, options)
        i = 0
        doc_location = options[:doc_location].to_s
        initial_did = currentDID["did"].to_s.dup
        initial_did = initial_did.delete_prefix("did:oyd:")
        if initial_did.include?(LOCATION_PREFIX)
            tmp = initial_did.split(LOCATION_PREFIX)
            initial_did = tmp[0] 
            doc_location = tmp[1]
        end
        if initial_did.include?(CGI.escape LOCATION_PREFIX)
            tmp = initial_did.split(CGI.escape LOCATION_PREFIX)
            initial_did = tmp[0] 
            doc_location = tmp[1]
        end
        doc_location = doc_location.gsub("%3A",":")
        doc_location = doc_location.gsub("%2F%2F","//")
        current_public_doc_key = ""
        verification_output = false
        currentDID["log"].each do |el|
            case el["op"]
            when 2,3 # CREATE, UPDATE
                currentDID["doc_log_id"] = i
                doc_did = el["doc"]
                did_hash = doc_did.delete_prefix("did:oyd:")
                did_hash = did_hash.split(LOCATION_PREFIX).first.split(CGI.escape LOCATION_PREFIX).first
                did10 = did_hash[0,10]

                doc = retrieve_document_raw(doc_did, did10 + ".doc", doc_location, {})
                if doc.first.nil?
                    currentDID["error"] = 2
                    msg = doc.last.to_s
                    if msg == ""
                        msg = "cannot retrieve " + doc_did.to_s
                    end
                    currentDID["message"] = msg
                    return currentDID
                end
                doc = doc.first["doc"]
                if el["op"] == 2 # CREATE
                    if !match_log_did?(el, doc)
                        currentDID["error"] = 1
                        currentDID["message"] = "Signatures in log don't match"
                        return currentDID
                    end
                end
                currentDID["did"] = doc_did
                currentDID["doc"] = doc
                # since hash is guaranteed during retrieve_document this check is not necessary
                # if hash(canonical(doc)) != did_hash
                #     currentDID["error"] = 1
                #     currentDID["message"] = "DID identifier and DID document don't match"
                #     if did_hash == initial_did
                #         verification_output = true
                #     end
                #     if verification_output
                #         currentDID["verification"] += "identifier: " + did_hash.to_s + "\n"
                #         currentDID["verification"] += "⛔ does not match DID Document:" + "\n"
                #         currentDID["verification"] += JSON.pretty_generate(doc) + "\n"
                #         currentDID["verification"] += "(Details: https://ownyourdata.github.io/oydid/#calculate_hash)" + "\n\n"
                #     end
                #     return currentDID
                # end
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
                did_hash = doc_did.delete_prefix("did:oyd:")
                did_hash = did_hash.split(LOCATION_PREFIX).first.split(CGI.escape LOCATION_PREFIX).first
                did10 = did_hash[0,10]
                doc = retrieve_document_raw(doc_did, did10 + ".doc", doc_location, {})
                # since it retrieves a DID that previously existed, this test is not necessary
                # if doc.first.nil?
                #     currentDID["error"] = 2
                #     currentDID["message"] = doc.last.to_s
                #     return currentDID
                # end
                doc = doc.first["doc"]
                term = doc["log"]
                log_location = term.split(LOCATION_PREFIX).last.split(CGI.escape LOCATION_PREFIX).last rescue ""
                if log_location.to_s == "" || log_location == term
                    log_location = DEFAULT_LOCATION
                end
                term = term.split(LOCATION_PREFIX).first.split(CGI.escape LOCATION_PREFIX).first
                log_options = options.dup
                el_hash = el["doc"].split(LOCATION_PREFIX).first.split(CGI.escape LOCATION_PREFIX).first
                log_options[:digest] = get_digest(el_hash).first
                log_options[:encode] = get_encoding(el_hash).first
                if multi_hash(canonical(el.slice("ts","op","doc","sig","previous")), log_options).first != term
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
                revoc_term = revoc_term.split(LOCATION_PREFIX).first.split(CGI.escape LOCATION_PREFIX).first
                revoc_term_found = false
                log_array, msg = retrieve_log(did_hash, did10 + ".log", log_location, options)
                log_array.each do |log_el|
                    log_el_structure = log_el.dup
                    if log_el["op"].to_i == 1 # TERMINATE
                        log_el_structure.delete("previous")
                    end
                    if multi_hash(canonical(log_el_structure.slice("ts","op","doc","sig","previous")), log_options).first == revoc_term
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
                # this should actually be covered by retrieve_log in the block above
                # (actually I wasn't able to craft a test case covering this part...)
                # if !options.transform_keys(&:to_s)["log_location"].nil?
                #     log_array, msg = retrieve_log(revoc_term, did10 + ".log", options.transform_keys(&:to_s)["log_location"], options)
                #     log_array.each do |log_el|
                #         if log_el["op"] == 1 # REVOKE
                #             log_el_structure = log_el.delete("previous")
                #         else
                #             log_el_structure = log_el
                #         end
                #         if hash(canonical(log_el_structure)) == revoc_term
                #             revoc_term_found = true
                #             revocation_record = log_el.dup
                #             if verification_output
                #                 currentDID["verification"] += "'doc' reference in TERMINATE log record: " + revoc_term.to_s + "\n"
                #                 currentDID["verification"] += "✅ is hash of REVOCATION log record (without 'previous' attribute):" + "\n"
                #                 currentDID["verification"] += JSON.pretty_generate(log_el) + "\n"
                #                 currentDID["verification"] += "(Details: https://ownyourdata.github.io/oydid/#calculate_hash)" + "\n\n"
                #             end
                #             break
                #         end
                #     end
                # end

                if revoc_term_found
                    update_term_found = false
                    log_array.each do |log_el|
                        if log_el["op"].to_i == 3
                            if log_el["previous"].include?(multi_hash(canonical(revocation_record), LOG_HASH_OPTIONS).first)
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
                                        next_doc_location = doc_location
                                        next_did_hash = next_doc_did.delete_prefix("did:oyd:")
                                        next_did_hash = next_did_hash.split(LOCATION_PREFIX).first.split(CGI.escape LOCATION_PREFIX).first
                                        next_did10 = next_did_hash[0,10]
                                        next_doc = retrieve_document_raw(next_doc_did, next_did10 + ".doc", next_doc_location, {})
                                        if next_doc.first.nil?
                                            currentDID["error"] = 2
                                            currentDID["message"] = next_doc.last
                                            return currentDID
                                        end
                                        next_doc = next_doc.first["doc"]
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
                                        new_doc_location = doc_location
                                        new_did_hash = new_doc_did.delete_prefix("did:oyd:")
                                        new_did_hash = new_did_hash.split(LOCATION_PREFIX).first.split(CGI.escape LOCATION_PREFIX).first
                                        new_did10 = new_did_hash[0,10]
                                        new_doc = retrieve_document(new_doc_did, new_did10 + ".doc", new_doc_location, {}).first
                                        currentDID["verification"] += "found UPDATE log record:" + "\n"
                                        currentDID["verification"] += JSON.pretty_generate(log_el) + "\n"
                                        currentDID["verification"] += "⛔ none of available public keys (" + pubKeys.join(", ") + ")\n"
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
end