module ApplicationHelperLegacy

    def oyd_encode_legacy(message)
        Multibases.pack("base58btc", message).to_s
    end

    def oyd_decode_legacy(message)
        Multibases.unpack(message).decode.to_s('ASCII-8BIT')
    end

    def oyd_hash_legacy(message)
        oyd_encode_legacy(Multihashes.encode(Digest::SHA256.digest(message), "sha2-256").unpack('C*'))
    end

    def add_hash_legacy(log)
        log.map do |item|
            i = item.dup
            i.delete("previous")
            item["entry-hash"] = oyd_hash_legacy(item.to_json)
            if item["op"] == 1
                item["sub-entry-hash"] = oyd_hash_legacy(i.to_json)
            end
            item
        end
    end

    def dag_did_legacy(logs, options)
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
            log_hash << oyd_hash_legacy(el.to_json)
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

    def dag2array_legacy(dag, log_array, index, result, options)
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
            dag2array_legacy(dag, log_array, s[:id], result, options)
        end unless dag.vertices[index].successors.count == 0
        result
    end

    def dag_update_legacy(currentDID)
        i = 0
        currentDID["log"].each do |el|
            case el["op"]
            when 2,3 # CREATE, UPDATE
                doc_did = el["doc"]
                doc_location = get_location_legacy(doc_did)
                did_hash = doc_did.delete_prefix("did:oyd:")
                did10 = did_hash[0,10]
                doc = retrieve_document_legacy(doc_did, did10 + ".doc", doc_location, {})
                if match_log_did_legacy?(el, doc)
                    currentDID["doc_log_id"] = i
                    currentDID["did"] = doc_did
                    currentDID["doc"] = doc
                end
            when 0 # TERMINATE
                currentDID["termination_log_id"] = i
            else
            end
            i += 1
        end unless currentDID["log"].nil?

        currentDID
    end

    def match_log_did_legacy?(log, doc)
        # check if signature matches current document
        # check if signature in log is correct
        publicKeys = doc["key"]
        pubKey_string = publicKeys.split(":")[0] rescue ""
        pubKey = Ed25519::VerifyKey.new(oyd_decode_legacy(pubKey_string))
        signature = oyd_decode_legacy(log["sig"])
        begin
            pubKey.verify(signature, log["doc"])
            return true
        rescue Ed25519::VerifyError
            return false
        end
    end

    def get_key_legacy(filename, key_type)
        begin
            f = File.open(filename)
            key_encoded = f.read
            f.close
        rescue
            return nil
        end
        if key_type == "sign"
            return Ed25519::SigningKey.new(oyd_decode_legacy(key_encoded))
        else
            return Ed25519::VerifyKey.new(oyd_decode_legacy(key_encoded))
        end
    end

    def get_file_legacy(filename)
        begin
            f = File.open(filename)
            content = f.read
            f.close
        rescue
            return nil
        end
        return content.to_s
    end

    def get_location_legacy(id)
        if id.include?(LOCATION_PREFIX)
            id_split = id.split(LOCATION_PREFIX)
            return id_split[1]
        else
            return DEFAULT_LOCATION
        end
    end

    def retrieve_document_legacy(doc_hash, doc_file, doc_location, options)
        if doc_location == ""
            doc_location = DEFAULT_LOCATION
        end

        case doc_location
        when /^http/
            if doc_location.start_with?('https://') || doc_location.start_with?('http://')
                retVal = HTTParty.get(doc_location + "/doc/" + doc_hash)
            elsif doc_location.start_with?('https:/') || doc_location.start_with?('http:/')
                retVal = HTTParty.get(doc_location.sub(":/", "://") + "/doc/" + doc_hash)
            else
                retVal = HTTParty.get(doc_location + "/doc/" + doc_hash)
            end
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

    def retrieve_log_legacy(did_hash, log_file, log_location, options)
        if log_location == ""
            log_location = DEFAULT_LOCATION
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
    def resolve_did_legacy(did, options)
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
        did_document = retrieve_document_legacy(did, did10 +  ".doc", did_location, options)

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
        log_array = retrieve_log_legacy(log_hash, did10 + ".log", log_location, options)
        if options[:trace]
            puts " .. Log retrieved"
        end

        dag, create_index, terminate_index = dag_did_legacy(log_array, options)
        if options[:trace]
            puts " .. DAG with " + dag.vertices.length.to_s + " vertices and " + dag.edges.length.to_s + " edges, CREATE index: " + create_index.to_s
        end
        ordered_log_array = dag2array_legacy(dag, log_array, create_index, [], options)
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
        currentDID = dag_update_legacy(currentDID)
        if options[:log_complete]
            currentDID["log"] = log_array
        end
        currentDID

    end

    def w3c_did_legacy(did_info)
        pubDocKey = did_info["doc"]["key"].split(":")[0] rescue ""
        pubRevKey = did_info["doc"]["key"].split(":")[1] rescue ""


        wd = {}
        wd["@context"] = "https://www.w3.org/ns/did/v1"
        wd["id"] = "did:oyd:" + did_info["did"]
        wd["verificationMethod"] = [{
            "id": "did:oyd:" + did_info["did"],
            "type": "Ed25519VerificationKey2018",
            "controller": "did:oyd:" + did_info["did"],
            "publicKeyBase58": pubDocKey
        }]
        wd["keyAgreement"] = [{
            "id": "did:oyd:" + did_info["did"],
            "type": "X25519KeyAgreementKey2019",
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