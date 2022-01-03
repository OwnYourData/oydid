module ApplicationHelper

    # functions for encoded messages ----------------

    def oyd_encode(message)
        Multibases.pack("base58btc", message).to_s
    end

    def oyd_decode(message)
        Multibases.unpack(message).decode.to_s('ASCII-8BIT')
    end

    # functions for hashing -------------------------

    def oyd_hash(message)
        oyd_encode(Multihashes.encode(Digest::SHA256.digest(message), "sha2-256").unpack('C*'))
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
        return oyd_encode([omc, length, raw_key].pack("SCa#{length}"))
    end

    def oyd_public_key(private_key)
        code, length, digest = oyd_decode(private_key).unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            public_key = Ed25519::SigningKey.new(digest).verify_key
            length = public_key.to_bytes.bytesize
            return oyd_encode([Multicodecs['ed25519-pub'].code, length, public_key].pack("CCa#{length}"))
        else
            puts "Error: unsupported key codec"
            return nil
        end
    end

    def oyd_sign(message, private_key)
        code, length, digest = oyd_decode(private_key).unpack('SCa*')
        case Multicodecs[code].name
        when 'ed25519-priv'
            return oyd_encode(Ed25519::SigningKey.new(digest).sign(message))
        else
            puts "Error: unsupported key codec"
            return nil
        end
    end

    def oyd_verify(message, signature, public_key)
        code, length, digest = oyd_decode(public_key).unpack('CCa*')
        begin
            case Multicodecs[code].name
            when 'ed25519-pub'
                verify_key = Ed25519::VerifyKey.new(digest)
                signature_verification = false
                begin
                    verify_key.verify(oyd_decode(signature), message)
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
        code, length, digest = oyd_decode(key_encoded).unpack('SCa*')
        begin
            case Multicodecs[code].name
            when 'ed25519-priv'
                private_key = Ed25519::SigningKey.new(digest).to_bytes
            else
                puts "Error: unsupported key codec"
                return nil
            end
            length = private_key.bytesize
            return oyd_encode([code, length, private_key].pack("SCa#{length}"))
        rescue
            puts "Error: invalid key"
            return nil
        end
    end

    # other functions ---------------------------

    def dag_did(logs)
        dag = DAG.new
        dag_log = []
        log_hash = []
        i = 0
        dag_log << dag.add_vertex(id: i)
        logs.each do |el|
            log = JSON.parse(el.first)
            i += 1
            dag_log << dag.add_vertex(id: i)
            log_hash << el.last
            if log["previous"] == []
                dag.add_edge from: dag_log[0], to: dag_log[i]
            else
                log["previous"].each do |p|
                    position = log_hash.find_index(p)
                    if !position.nil?
                        dag.add_edge from: dag_log[position+1], to: dag_log[i]
                    end
                end
            end
        end unless logs.nil?
        return dag
    end

    def dag_update(vertex, logs, currentDID)
        vertex.successors.each do |v|
            current_log = logs[v[:id].to_i - 1]
            if currentDID["last_id"].nil?
                currentDID["last_id"] = current_log.first["id"].to_i
            else
                if currentDID["last_id"].to_i < current_log.first["id"].to_i
                    currentDID["last_id"] = current_log.first["id"].to_i
                end
            end
            case current_log.first["op"]
            when 2,3 # CREATE, UPDATE
                doc_did = current_log.first["doc"]
                doc_location = get_location(doc_did)
                did_hash = doc_did.delete_prefix("did:oyd:")
                did10 = did_hash[0,10]
                doc = retrieve_document(doc_did, did10 + ".doc", doc_location, {})
                # check if sig matches did doc 
                if match_log_did?(current_log.first, doc)
                    currentDID["doc_log_id"] = v[:id].to_i
                    currentDID["did"] = doc_did
                    currentDID["doc"] = doc
                    if currentDID["last_sign_id"].nil?
                        currentDID["last_sign_id"] = current_log.first["id"].to_i
                    else
                        if currentDID["last_sign_id"].to_i < current_log.first["id"].to_i
                            currentDID["last_sign_id"] = current_log.first["id"].to_i
                        end
                    end
                end
            when 0
                # TODO: check if termination document exists
                currentDID["termination_log_id"] = v[:id].to_i
            end

            if v.successors.count > 0
                currentDID = dag_update(v, logs, currentDID)
            end
        end
        return currentDID
    end

    def match_log_did?(log, doc)
        # check if signature matches current document
        # check if signature in log is correct
        publicKeys = doc["key"]
        pubKey_string = publicKeys.split(":")[0] rescue ""
        pubKey = Ed25519::VerifyKey.new(oyd_decode(pubKey_string))
        signature = oyd_decode(log["sig"])
        begin
            pubKey.verify(signature, log["doc"])
            return true
        rescue Ed25519::VerifyError
            return false
        end
    end

    def get_key(filename, key_type)
        begin
            f = File.open(filename)
            key_encoded = f.read
            f.close
        rescue
            return nil
        end
        if key_type == "sign"
            return Ed25519::SigningKey.new(oyd_decode(key_encoded))
        else
            return Ed25519::VerifyKey.new(oyd_decode(key_encoded))
        end
    end

    def get_location(id)
        if id.include?(LOCATION_PREFIX)
            id_split = id.split(LOCATION_PREFIX)
            return id_split[1]
        else
            return nil
        end
    end

    def retrieve_document(doc_hash, doc_file, doc_location, options)
        @did = Did.find_by_did(doc_hash)
        if !@did.nil?
            doc = JSON.parse(@did.doc) rescue nil
            return doc
        end
        case doc_location
        when /^http/
            return nil
        when "local"
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
end
