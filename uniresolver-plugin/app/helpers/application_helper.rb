module ApplicationHelper

    # functions for hashing -------------------------

    def oyd_hash(message)
        Oydid.encode(Multihashes.encode(Digest::SHA256.digest(message), "sha2-256").unpack('C*'))
    end

    def oyd_canonical(message)
        if message.is_a? String
            message = JSON.parse(message) rescue message
        else
            message = JSON.parse(message.to_json) rescue message
        end
        message.to_json_c14n
    end

    # functions for key management ------------------

    def oyd_generate_private_key(input, method)
        begin
            omc = Multicodecs[method].code
        rescue
            puts "Error: unknown key codec"
            return nil
        end
        
        case Multicodecs[method].name 
        when 'ed25519-priv'
            if input != ""
                raw_key = Ed25519::SigningKey.new(RbNaCl::Hash.sha256(input)).to_bytes
            else
                raw_key = Ed25519::SigningKey.generate.to_bytes
            end
        else
            puts "Error: unsupported key codec"
            return nil
        end
        length = raw_key.bytesize
        return Oydid.encode([omc, length, raw_key].pack("SCa#{length}"))
    end

    def oyd_public_key(private_key)
        code, length, digest = Oydid.decode(private_key).unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            public_key = Ed25519::SigningKey.new(digest).verify_key
            length = public_key.to_bytes.bytesize
            return Oydid.encode([Multicodecs['ed25519-pub'].code, length, public_key].pack("CCa#{length}"))
        else
            puts "Error: unsupported key codec"
            return nil
        end
    end

    def oyd_sign(message, private_key)
        code, length, digest = Oydid.decode(private_key).unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            return Oydid.encode(Ed25519::SigningKey.new(digest).sign(message))
        else
            puts "Error: unsupported key codec"
            return nil
        end
    end

    def oyd_verify(message, signature, public_key)
        code, length, digest = Oydid.decode(public_key).unpack('CCa*')
        begin
            case Multicodecs[code].name
            when 'ed25519-pub'
                verify_key = Ed25519::VerifyKey.new(digest)
                signature_verification = false
                begin
                    verify_key.verify(Oydid.decode(signature), message)
                    signature_verification = true
                rescue Ed25519::VerifyError
                    signature_verification = false
                end
            else
                puts "Error: unsupported key codec"
                return nil
            end
        rescue
            puts "Error: unknown codec"
            return nil
        end
    end

    def read_private_key(filename)
        begin
            f = File.open(filename)
            key_encoded = f.read
            f.close
        rescue
            return nil
        end
        code, length, digest = Oydid.decode(key_encoded).unpack('SCa*')
        begin
            case Multicodecs[code].name
            when 'ed25519-priv'
                private_key = Ed25519::SigningKey.new(digest).to_bytes
            else
                puts "Error: unsupported key codec"
                return nil
            end
            length = private_key.bytesize
            return Oydid.encode([code, length, private_key].pack("SCa#{length}"))
        rescue
            puts "Error: invalid key"
            return nil
        end
    end

    # storage functions -----------------------------

    def write_private_storage(payload, filename)
        File.write(filename, payload)
    end

    def read_private_storage(filename)
        begin
            f = File.open(filename)
            content = f.read
            f.close
        rescue
            return nil
        end
        return content.to_s
    end

    # other functions -------------------------------

    def add_hash(log)
        log.map do |item|
            i = item.dup
            i.delete("previous")
            item["entry-hash"] = oyd_hash(oyd_canonical(item))
            if item["op"] == 1
                item["sub-entry-hash"] = oyd_hash(oyd_canonical(i))
            end
            item
        end
    end

    def dag_did(logs, options)
        dag = DAG.new
        dag_log = []
        log_hash = []
        
        # calculate hash values for each entry and build vertices
        i = 0
        create_entries = 0
        create_index = nil
        terminate_indices = []
        logs.each do |el|
            if el["op"].to_i == 2
                create_entries += 1
                create_index = i
            end
            if el["op"].to_i == 0
                terminate_indices << i
            end
            log_hash << oyd_hash(oyd_canonical(el))
            dag_log << dag.add_vertex(id: i)
            i += 1
        end unless logs.nil?

        if create_entries != 1
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: wrong number of CREATE entries (" + create_entries.to_s + ") in log"
                else
                    puts '{"error": "wrong number of CREATE entries (' + create_entries.to_s + ') in log"}'
                end
            end
            exit(1)
        end
        if terminate_indices.length == 0
           if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: missing TERMINATE entries"
                else
                    puts '{"error": "missing TERMINATE entries"}'
                end
            end
            exit(1)
        end 

        # create edges between vertices
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
                end
                terminate_overall += 1
                terminate_index = i
            end
            i += 1
        end unless logs.nil?

        if terminate_entries != 1 && !options[:log_complete]
           if options[:silent].nil? || !options[:silent]
                # if terminate_overall > 0
                #     if options[:json].nil? || !options[:json]
                #         puts "Error: invalid number of tangling TERMINATE entries (" + terminate_entries.to_s + ")"
                #     else
                #         puts '{"error": "invalid number of tangling TERMINATE entries (' + terminate_entries.to_s + ')"}'
                #     end
                # else
                    if options[:json].nil? || !options[:json]
                        puts "Error: cannot resolve DID"
                    else
                        puts '{"error": "cannot resolve DID"}'
                    end
                # end
            end
            exit(1)
        end 

        return [dag, create_index, terminate_index]
    end

    def dag2array(dag, log_array, index, result, options)
        if options[:trace]
            if options[:silent].nil? || !options[:silent]
                puts "    vertex " + index.to_s + " at " + log_array[index]["ts"].to_s + " op: " + log_array[index]["op"].to_s + " doc: " + log_array[index]["doc"].to_s
            end
        end
        result << log_array[index]
        dag.vertices[index].successors.each do |s|
            # check if successor has predecessor that is not self (i.e. REVOKE with TERMINATE)
            s.predecessors.each do |p|
                if p[:id] != index
                    if options[:trace]
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

    def dag_update(currentDID, options)
        i = 0
        initial_did = currentDID["did"]
        initial_did = initial_did.delete_prefix("did:oyd:")
        initial_did = initial_did.split("@").first
        current_public_doc_key = ""
        verification_output = false
        currentDID["log"].each do |el|
            case el["op"]
            when 2,3 # CREATE, UPDATE
                doc_did = el["doc"]
                doc_location = get_location(doc_did)
                did_hash = doc_did.delete_prefix("did:oyd:")
                did_hash = did_hash.split("@").first
                did10 = did_hash[0,10]
                doc = retrieve_document(doc_did, did10 + ".doc", doc_location, {})
                if el["op"] == 2 # CREATE
                    if match_log_did?(el, doc)
                        currentDID["doc_log_id"] = i
                    else
                        currentDID["error"] = 1
                        currentDID["message"] = "Signatures in log don't match"
                        return currentDID
                        break
                    end
                end
                currentDID["did"] = doc_did
                currentDID["doc"] = doc
                if oyd_hash(oyd_canonical(doc)) != did_hash
                    currentDID["error"] = 1
                    currentDID["message"] = "DID identifier and DID document don't match"
                    if options[:show_verification]
                        if did_hash == initial_did
                            verification_output = true
                        end
                        if verification_output
                            puts "identifier: " + did_hash.to_s
                            puts "NOK: does not match DID Document:"
                            puts JSON.pretty_generate(doc)
                            puts "(Details: https://ownyourdata.github.io/oydid/#calculate_hash)"
                            puts ""
                        end
                    end
                    return currentDID
                    break
                end
                if options[:show_verification]
                    if did_hash == initial_did
                        verification_output = true
                    end
                    if verification_output
                        puts "identifier: " + did_hash.to_s
                        puts "OK: is hash of DID Document:"
                        puts JSON.pretty_generate(doc)
                        puts "(Details: https://ownyourdata.github.io/oydid/#calculate_hash)"
                        puts ""
                    end
                end
                current_public_doc_key = currentDID["doc"]["key"].split(":").first rescue ""

            when 0 # TERMINATE
                currentDID["termination_log_id"] = i

                doc_did = currentDID["did"]
                doc_location = get_location(doc_did)
                did_hash = doc_did.delete_prefix("did:oyd:")
                did_hash = did_hash.split("@").first
                did10 = did_hash[0,10]
                doc = retrieve_document(doc_did, did10 + ".doc", doc_location, {})
                term = doc["log"]
                log_location = term.split("@")[1] rescue ""
                if log_location.to_s == ""
                    log_location = DEFAULT_LOCATION
                end
                term = term.split("@").first
                if oyd_hash(oyd_canonical(el)) != term
                    currentDID["error"] = 1
                    currentDID["message"] = "Log reference and record don't match"
                    if options[:show_verification]
                        if verification_output
                            puts "'log' reference in DID Document: " + term.to_s
                            puts "NOK: does not match TERMINATE log record:"
                            puts JSON.pretty_generate(el)
                            puts "(Details: https://ownyourdata.github.io/oydid/#calculate_hash)"
                            puts ""
                        end
                    end
                    return currentDID
                    break
                end
                if options[:show_verification]
                    if verification_output
                        puts "'log' reference in DID Document: " + term.to_s
                        puts "OK: is hash of TERMINATE log record:"
                        puts JSON.pretty_generate(el)
                        puts "(Details: https://ownyourdata.github.io/oydid/#calculate_hash)"
                        puts ""
                    end
                end

                # check if there is a revocation entry
                revocation_record = {}
                revoc_term = el["doc"]
                revoc_term = revoc_term.split("@").first
                revoc_term_found = false
                log_array = retrieve_log(did_hash, did10 + ".log", log_location, options)
                log_array.each do |log_el|
                    log_el_structure = log_el.dup
                    if log_el["op"] == 1 # TERMINATE
                        log_el_structure.delete("previous")
                    end
                    if oyd_hash(oyd_canonical(log_el_structure)) == revoc_term
                        revoc_term_found = true
                        revocation_record = log_el.dup
                        if options[:show_verification]
                            if verification_output
                                puts "'doc' reference in TERMINATE log record: " + revoc_term.to_s
                                puts "OK: is hash of REVOCATION log record (without 'previous' attribute):"
                                puts JSON.pretty_generate(log_el)
                                puts "(Details: https://ownyourdata.github.io/oydid/#calculate_hash)"
                                puts ""
                            end
                        end
                        break
                    end
                end unless log_array.nil?

                if !options[:log_location].nil?
                    log_array = retrieve_log(revoc_term, did10 + ".log", options[:log_location], options)
                    log_array.each do |log_el|
                        if log_el["op"] == 1 # TERMINATE
                            log_el_structure = log_el.delete("previous")
                        else
                            log_el_structure = log_el
                        end
                        if oyd_hash(oyd_canonical(log_el_structure)) == revoc_term
                            revoc_term_found = true
                            revocation_record = log_el.dup
                            if options[:show_verification]
                                if verification_output
                                    puts "'doc' reference in TERMINATE log record: " + revoc_term.to_s
                                    puts "OK: is hash of REVOCATION log record (without 'previous' attribute):"
                                    puts JSON.pretty_generate(log_el)
                                    puts "(Details: https://ownyourdata.github.io/oydid/#calculate_hash)"
                                    puts ""
                                end
                            end
                            break
                        end
                    end
                end

                if revoc_term_found
                    update_term_found = false
                    log_array.each do |log_el|
                        if log_el["op"] == 3
                            if log_el["previous"].include?(oyd_hash(oyd_canonical(revocation_record)))
                                update_term_found = true
                                message = log_el["doc"].to_s

                                signature = log_el["sig"]
                                public_key = current_public_doc_key.to_s
                                signature_verification = oyd_verify(message, signature, public_key)
                                if signature_verification
                                    if options[:show_verification]
                                        if verification_output
                                            puts "found UPDATE log record:"
                                            puts JSON.pretty_generate(log_el)
                                            puts "OK: public key from last DID Document: " + current_public_doc_key.to_s
                                            puts "verifies 'doc' reference of new DID Document: " + log_el["doc"].to_s
                                            puts log_el["sig"].to_s
                                            puts "of next DID Document (Details: https://ownyourdata.github.io/oydid/#verify_signature)"

                                            next_doc_did = log_el["doc"].to_s
                                            next_doc_location = get_location(next_doc_did)
                                            next_did_hash = next_doc_did.delete_prefix("did:oyd:")
                                            next_did_hash = next_did_hash.split("@").first
                                            next_did10 = next_did_hash[0,10]
                                            next_doc = retrieve_document(next_doc_did, next_did10 + ".doc", next_doc_location, {})
                                            if public_key == next_doc["key"].split(":").first
                                                puts "NOK: no key rotation in updated DID Document"
                                            end

                                            puts ""
                                        end
                                    end
                                else
                                    currentDID["error"] = 1
                                    currentDID["message"] = "Signature does not match"
                                    if options[:show_verification]
                                        if verification_output
                                            puts "found UPDATE log record:"
                                            puts JSON.pretty_generate(log_el)
                                            puts "NOK: public key from last DID Document: " + current_public_doc_key.to_s
                                            puts "does not verify 'doc' reference of new DID Document: " + log_el["doc"].to_s
                                            puts log_el["sig"].to_s
                                            puts "next DID Document (Details: https://ownyourdata.github.io/oydid/#verify_signature)"
                                            puts JSON.pretty_generate(new_doc)
                                            puts ""
                                        end
                                    end
                                    return currentDID
                                end
                                break
                            end
                        end
                    end

                else
                    if options[:show_verification]
                        if verification_output
                            puts "Revocation reference in log record: " + revoc_term.to_s
                            puts "OK: cannot find revocation record searching at"
                            puts "- " + log_location
                            if !options[:log_location].nil?
                                puts "- " + options[:log_location].to_s
                            end
                            puts "(Details: https://ownyourdata.github.io/oydid/#retrieve_log)"
                            puts ""
                        end
                    end
                    break
                end
            else

            end
            i += 1
        end unless currentDID["log"].nil?

        currentDID
    end

    def match_log_did?(log, doc)
        # check if signature matches current document
        # check if signature in log is correct
        message = log["doc"]
        signature = log["sig"]
        public_keys = doc["key"]
        public_key = public_keys.split(":")[0] rescue ""
        return oyd_verify(message, signature, public_key)
    end

    def get_location(id)
        if id.include?(LOCATION_PREFIX)
            id_split = id.split(LOCATION_PREFIX)
            return id_split[1]
        else
            return DEFAULT_LOCATION
        end
    end

    def retrieve_document(doc_hash, doc_file, doc_location, options)
        if doc_location == ""
            doc_location = DEFAULT_LOCATION
        end
        if !(doc_location == "" || doc_location == "local")
            if !doc_location.start_with?("http")
                doc_location = "https://" + doc_location
            end
        end

        case doc_location
        when /^http/
            retVal = HTTParty.get(doc_location + "/doc/" + doc_hash)
            if retVal.code != 200
                if options[:json].nil? || !options[:json]
                    puts "Registry Error: " + retVal.parsed_response("error").to_s rescue 
                        puts "Error: invalid response from " + doc_location.to_s + "/doc/" + doc_hash.to_s
                else
                    puts '{"error": "' + retVal.parsed_response['error'].to_s + '", "source": "registry"}' rescue
                        puts '{"error": "invalid response from ' + doc_location.to_s + "/doc/" + doc_hash.to_s + '"}'
                end
                exit(1)
            end
            if options[:trace]
                if options[:silent].nil? || !options[:silent]
                    puts "GET " + doc_hash + " from " + doc_location
                end
            end
            return retVal.parsed_response
        when "", "local"
            doc = {}
            begin
                f = File.open(doc_file)
                doc = JSON.parse(f.read) rescue {}
                f.close
            rescue

            end
            if doc == {}
                return nil
            end
        else
            return nil
        end
        return doc

    end

    def retrieve_log(did_hash, log_file, log_location, options)
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
            retVal = HTTParty.get(log_location + "/log/" + did_hash)
            if retVal.code != 200
                if options[:silent].nil? || !options[:silent]
                    if options[:json].nil? || !options[:json]
                        puts "Registry Error: " + retVal.parsed_response("error").to_s rescue 
                            puts "Error: invalid response from " + log_location.to_s + "/log/" + did_hash.to_s
                    else
                        puts '{"error": "' + retVal.parsed_response['error'].to_s + '", "source": "registry"}' rescue
                            puts '{"error": "invalid response from ' + log_location.to_s + "/log/" + did_hash.to_s + '"}'
                    end
                end
                exit(1)
            end
            if options[:trace]
                if options[:silent].nil? || !options[:silent]
                    puts "GET log for " + did_hash + " from " + log_location
                end
            end
            retVal = JSON.parse(retVal.to_s) rescue nil
            return retVal
        when "", "local"
            doc = {}
            begin
                f = File.open(log_file)
                doc = JSON.parse(f.read) rescue {}
                f.close
            rescue

            end
            if doc == {}
                return nil
            end
        else
            return nil
        end
        return doc
    end

    # expected DID format: did:oyd:123
    def resolve_did(did, options)
        # setup
        currentDID = {
            "did": did,
            "doc": "",
            "log": [],
            "doc_log_id": nil,
            "termination_log_id": nil,
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
        if did_location.to_s == ""
            if did.include?(LOCATION_PREFIX)
                tmp = did.split(LOCATION_PREFIX)
                did = tmp[0] 
                did_location = tmp[1]
            end
        end
        if did_location == ""
            did_location = DEFAULT_LOCATION
        end

        # retrieve DID document
        did_document = retrieve_document(did, did10 +  ".doc", did_location, options)
        if did_document.nil?
            return nil
        end
        currentDID["doc"] = did_document
        if options[:trace]
            puts " .. DID document retrieved"
        end

        # get log location
        log_hash = did_document["log"]
        log_location = ""
        if !options[:log_location].nil?
            log_location = options[:log_location]
        end
        if log_location.to_s == ""
            if !options[:location].nil?
                log_location = options[:location]
            end
        end
        if log_location.to_s == ""
            if log_hash.include?(LOCATION_PREFIX)
                hash_split = log_hash.split(LOCATION_PREFIX)
                log_hash = hash_split[0]
                log_location = hash_split[1]
            end
        end
        if log_location == ""
            log_location = DEFAULT_LOCATION
        end

        # retrieve and traverse log to get current DID state
        log_array = retrieve_log(log_hash, did10 + ".log", log_location, options)
        if options[:trace]
            puts " .. Log retrieved"
        end
        dag, create_index, terminate_index = dag_did(log_array, options)
        if options[:trace]
            puts " .. DAG with " + dag.vertices.length.to_s + " vertices and " + dag.edges.length.to_s + " edges, CREATE index: " + create_index.to_s
        end
        ordered_log_array = dag2array(dag, log_array, create_index, [], options)
        if options[:trace]
            if options[:silent].nil? || !options[:silent]
                puts "    vertex " + terminate_index.to_s + " at " + log_array[terminate_index]["ts"].to_s + " op: " + log_array[terminate_index]["op"].to_s + " doc: " + log_array[terminate_index]["doc"].to_s
            end
        end
        ordered_log_array << log_array[terminate_index]
        currentDID["log"] = ordered_log_array
        if options[:trace]
            if options[:silent].nil? || !options[:silent]
                dag.edges.each do |e|
                    puts "    edge " + e.origin[:id].to_s + " <- " + e.destination[:id].to_s
                end
            end
        end
        currentDID = dag_update(currentDID, options)
        if options[:log_complete]
            currentDID["log"] = log_array
        end
        currentDID

    end

    def w3c_did(did_info, options)
        pubDocKey = did_info["doc"]["key"].split(":")[0] rescue ""
        pubRevKey = did_info["doc"]["key"].split(":")[1] rescue ""

        wd = {}
        wd["@context"] = "https://www.w3.org/ns/did/v1"
        wd["id"] = "did:oyd:" + did_info["did"]
        wd["verificationMethod"] = [{
            "id": "did:oyd:" + did_info["did"],
            "type": "Ed25519VerificationKey2020",
            "controller": "did:oyd:" + did_info["did"],
            "publicKeyBase58": pubDocKey
        }]
        wd["keyAgreement"] = [{
            "id": "did:oyd:" + did_info["did"],
            "type": "Ed25519VerificationKey2020",
            "controller": "did:oyd:" + did_info["did"],
            "publicKeyBase58": pubRevKey
        }]
        if did_info["doc"]["doc"].is_a?(Array)
            wd["service"] = did_info["doc"]["doc"]
        else
            wd["service"] = [did_info["doc"]["doc"]]
        end
        return wd
    end

end