#!/usr/bin/env ruby
# encoding: utf-8

require 'multibases'
require 'multihashes'
require 'multicodecs'
require 'digest'
require 'securerandom'
require 'httparty'
require 'ed25519'
require 'optparse'
require 'rbnacl'
require 'dag'
require 'uri'
require 'json/canonicalization'

LOCATION_PREFIX = "@"
DEFAULT_LOCATION = "https://oydid.ownyourdata.eu"
VERSION = "0.4.5"

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

# def get_key(filename, key_type) -> replace with read_private_key
#     begin
#         f = File.open(filename)
#         key_encoded = f.read
#         f.close
#     rescue
#         return nil
#     end
#     if key_type == "sign"
#         return Ed25519::SigningKey.new(oyd_decode(key_encoded))
#     else
#         return Ed25519::VerifyKey.new(oyd_decode(key_encoded))
#     end
# end

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
                        puts "⛔ does not match DID Document:"
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
                    puts "✅ is hash of DID Document:"
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
                        puts "⛔ does not match TERMINATE log record:"
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
                    puts "✅ is hash of TERMINATE log record:"
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
                            puts "✅ is hash of REVOCATION log record (without 'previous' attribute):"
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
                                puts "✅ is hash of REVOCATION log record (without 'previous' attribute):"
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
                                        puts "✅ public key from last DID Document: " + current_public_doc_key.to_s
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
                                            puts "⚠️  no key rotation in updated DID Document"
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
                                        puts "⛔ public key from last DID Document: " + current_public_doc_key.to_s
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
                        puts "✅ cannot find revocation record searching at"
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

def delete_did(did, options)
    doc_location = options[:doc_location]
    if doc_location.to_s == ""
        if did.include?(LOCATION_PREFIX)
            hash_split = did.split(LOCATION_PREFIX)
            did = hash_split[0]
            doc_location = hash_split[1]
        end
    end
    if doc_location.to_s == ""
        doc_location = DEFAULT_LOCATION
    end
    did = did.delete_prefix("did:oyd:")

    if options[:doc_key].nil?
        if options[:doc_pwd].nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: missing document key"
                else
                    puts '{"error": "missing document key"}'
                end
            end
            exit 1
        else
            privateKey = oyd_generate_private_key(options[:doc_pwd].to_s, 'ed25519-priv')
        end
    else
        privateKey = read_private_key(options[:doc_key].to_s)
        if privateKey.nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: missing document key"
                else
                    puts '{"error": "missing document key"}'
                end
            end
            exit 1
        end        
    end
    if options[:rev_key].nil?
        if options[:rev_pwd].nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: missing revocation key"
                else
                    puts '{"error": "missing revocation key"}'
                end
            end
            exit 1
        else
            revocationKey = oyd_generate_private_key(options[:rev_pwd].to_s, 'ed25519-priv')
        end
    else
        revocationKey = read_private_key(options[:rev_key].to_s)
        if revocationKey.nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: missing revocation key"
                else
                    puts '{"error": "missing revocation key"}'
                end
            end
            exit 1
        end
    end

    did_data = {
        "dockey": privateKey,
        "revkey": revocationKey
    }
    oydid_url = doc_location.to_s + "/doc/" + did.to_s
    retVal = HTTParty.delete(oydid_url,
        headers: { 'Content-Type' => 'application/json' },
        body: did_data.to_json )
    if retVal.code != 200
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Registry Error: " + retVal.parsed_response("error").to_s rescue 
                    puts "Error: invalid response from " + oydid_url.to_s
            else
                puts '{"error": "' + retVal.parsed_response['error'].to_s + '", "source": "registry"}' rescue
                    puts '{"error": "invalid response from ' + oydid_url.to_s + '"}'
            end
        end
        exit 1
    end
end

def write_did(content, did, mode, options)
    # generate did_doc and did_key
    did_doc = JSON.parse(content.join("")) rescue {}
    if did_doc == {}
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: empty or invalid payload"
            else
                puts '{"error": "empty or invalid payload"}'
            end
        end
        exit 1
    end        
    did_old = nil
    log_old = nil
    prev_hash = []
    revoc_log = nil
    doc_location = options[:doc_location]
    if options[:ts].nil?
        ts = Time.now.to_i
    else
        ts = options[:ts]
    end

    if mode == "create" || mode == "clone"
        operation_mode = 2 # CREATE
        if options[:doc_key].nil?
            privateKey = oyd_generate_private_key(options[:doc_pwd].to_s, 'ed25519-priv')
        else
            privateKey = read_private_key(options[:doc_key].to_s)
            if privateKey.nil?
                if options[:silent].nil? || !options[:silent]
                    if options[:json].nil? || !options[:json]
                        puts "Error: private key not found"
                    else
                        puts '{"error": "private key not found"}'
                    end
                end
                exit 1
            end
        end
        if options[:rev_key].nil?
            revocationKey = oyd_generate_private_key(options[:rev_pwd].to_s, 'ed25519-priv')
        else
            revocationKey = read_private_key(options[:rev_key].to_s)
            if privateKey.nil?
                if options[:silent].nil? || !options[:silent]
                    if options[:json].nil? || !options[:json]
                        puts "Error: private revocation not found"
                    else
                        puts '{"error": "revocation key not found"}'
                    end
                end
                exit 1
            end
        end
    else # mode == "update"  => read information
        did_info = resolve_did(did, options)
        if did_info.nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: cannot resolve DID (on updating DID)"
                else
                    puts '{"error": "cannot resolve DID (on updating DID)"}'
                end
            end
            exit (-1)
        end
        if did_info["error"] != 0
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: " + did_info["message"].to_s
                else
                    puts '{"error": "' + did_info["message"].to_s + '"}'
                end
            end
            exit(1)
        end

        did = did_info["did"]
        did_hash = did.delete_prefix("did:oyd:")
        did10 = did_hash[0,10]
        if doc_location.to_s == ""
            if did_hash.include?(LOCATION_PREFIX)
                hash_split = did_hash.split(LOCATION_PREFIX)
                did_hash = hash_split[0]
                doc_location = hash_split[1]
            end
        end
        operation_mode = 3 # UPDATE

        # collect relevant information from previous did
        did_old = did.dup
        did10_old = did10.dup
        log_old = did_info["log"]
        privateKey_old = read_private_storage(did10_old + "_private_key.b58")
        revocationKey_old = read_private_storage(did10_old + "_revocation_key.b58")

        # key management
        if options[:doc_key].nil?
            privateKey = oyd_generate_private_key(options[:doc_pwd].to_s, 'ed25519-priv')
        else
            privateKey = read_private_key(options[:doc_key].to_s)
        end
        if options[:rev_key].nil? && options[:rev_pwd].nil?
            revocationKey = oyd_generate_private_key("", 'ed25519-priv')
            revocationLog = read_private_storage(did10 + "_revocation.json")
        else
            if options[:rev_key].nil?
                revocationKey = oyd_generate_private_key(options[:rev_pwd].to_s, 'ed25519-priv')
            else
                revocationKey = read_private_key(options[:rev_key].to_s)
            end

            # re-build revocation document
            did_old_doc = did_info["doc"]["doc"]
            ts_old = did_info["log"].last["ts"]
            publicKey_old = oyd_public_key(privateKey_old)
            pubRevoKey_old = oyd_public_key(revocationKey_old)
            did_key_old = publicKey_old + ":" + pubRevoKey_old
            subDid = {"doc": did_old_doc, "key": did_key_old}.to_json
            subDidHash = oyd_hash(subDid)
            signedSubDidHash = oyd_sign(subDidHash, revocationKey_old)
            revocationLog = { 
                "ts": ts_old,
                "op": 1, # REVOKE
                "doc": subDidHash,
                "sig": signedSubDidHash }.transform_keys(&:to_s).to_json
        end
        revoc_log = JSON.parse(revocationLog)
        revoc_log["previous"] = [
            oyd_hash(oyd_canonical(log_old[did_info["doc_log_id"].to_i])), 
            oyd_hash(oyd_canonical(log_old[did_info["termination_log_id"].to_i]))
        ]
        prev_hash = [oyd_hash(oyd_canonical(revoc_log))]
    end

    publicKey = oyd_public_key(privateKey)
    pubRevoKey = oyd_public_key(revocationKey)
    did_key = publicKey + ":" + pubRevoKey

    # build new revocation document
    subDid = {"doc": did_doc, "key": did_key}.to_json
    subDidHash = oyd_hash(oyd_canonical(subDid))
    signedSubDidHash = oyd_sign(subDidHash, revocationKey)
    r1 = { "ts": ts,
           "op": 1, # REVOKE
           "doc": subDidHash,
           "sig": signedSubDidHash }.transform_keys(&:to_s)

    # build termination log entry
    l2_doc = oyd_hash(oyd_canonical(r1))
    if !doc_location.nil?
        l2_doc += LOCATION_PREFIX + doc_location.to_s
    end
    l2 = { "ts": ts,
           "op": 0, # TERMINATE
           "doc": l2_doc,
           "sig": oyd_sign(l2_doc, privateKey),
           "previous": [] }.transform_keys(&:to_s)

    # build actual DID document
    log_str = oyd_hash(oyd_canonical(l2))
    if !doc_location.nil?
        log_str += LOCATION_PREFIX + doc_location.to_s
    end
    didDocument = { "doc": did_doc,
                    "key": did_key,
                    "log": log_str }.transform_keys(&:to_s)

    # create DID
    l1_doc = oyd_hash(oyd_canonical(didDocument))
    if !doc_location.nil?
        l1_doc += LOCATION_PREFIX + doc_location.to_s
    end    
    did = "did:oyd:" + l1_doc
    did10 = l1_doc[0,10]
    if doc_location.to_s == ""
        doc_location = DEFAULT_LOCATION
    end

    if mode == "clone"
        # create log entry for source DID
        new_log = {
            "ts": ts,
            "op": 4, # CLONE
            "doc": l1_doc,
            "sig": oyd_sign(l1_doc, privateKey),
            "previous": [options[:previous_clone].to_s]
        }
        retVal = HTTParty.post(options[:source_location] + "/log/" + options[:source_did],
            headers: { 'Content-Type' => 'application/json' },
            body: {"log": new_log}.to_json )
        prev_hash = [oyd_hash(oyd_canonical(new_log))]
    end

    # build creation log entry
    if operation_mode == 3 # UPDATE
        l1 = { "ts": ts,
               "op": operation_mode, # UPDATE
               "doc": l1_doc,
               "sig": oyd_sign(l1_doc, privateKey_old),
               "previous": prev_hash }.transform_keys(&:to_s)
    else        
        l1 = { "ts": ts,
               "op": operation_mode, # CREATE
               "doc": l1_doc,
               "sig": oyd_sign(l1_doc, privateKey),
               "previous": prev_hash }.transform_keys(&:to_s)
    end

    # wirte data based on location
    case doc_location.to_s
    when /^http/
        # build object to post
        did_data = {
            "did": did,
            "did-document": didDocument,
            "logs": [revoc_log, l1, l2].flatten.compact
        }
        oydid_url = doc_location.to_s + "/doc"
        retVal = HTTParty.post(oydid_url,
            headers: { 'Content-Type' => 'application/json' },
            body: did_data.to_json )
        if retVal.code != 200
            if options[:json].nil? || !options[:json]
                puts "Registry Error: " + retVal.parsed_response("error").to_s rescue 
                    puts "Error: invalid response from " + doc_location.to_s + "/doc"
            else
                puts '{"error": "' + retVal.parsed_response['error'].to_s + '", "source": "registry"}' rescue
                    puts '{"error": "invalid response from ' + doc_location.to_s + "/doc" + '"}'
            end
            exit(1)            
        end
    else
        # write files to disk
        File.write(did10 + ".log", [log_old, revoc_log, l1, l2].flatten.compact.to_json)
        if !did_old.nil?
            File.write(did10_old + ".log", [log_old, revoc_log, l1, l2].flatten.compact.to_json)
        end
        File.write(did10 + ".doc", didDocument.to_json)
        File.write(did10 + ".did", did)
    end
    write_private_storage(privateKey, did10 + "_private_key.b58")
    write_private_storage(revocationKey, did10 + "_revocation_key.b58")
    write_private_storage(r1.to_json, did10 + "_revocation.json")


    if options[:silent].nil? || !options[:silent]
        # write DID to stdout
        if options[:json].nil? || !options[:json]
            case mode
            when "create"
                puts "created " + did
            when "clone"
                puts "cloned " + did
            when "update"
                puts "updated " + did
            end
        else
            case mode
            when "create"
                puts '{"did": "did:oyd:"' + did.to_s + '", "operation": "create"}'
            when "clone"
                puts '{"did": "did:oyd:"' + did.to_s + '", "operation": "clone"}'
            when "update"
                puts '{"did": "did:oyd:"' + did.to_s + '", "operation": "update"}'
            end
        end
    end
    did
end

def revoke_did(did, options)
    doc_location = options[:doc_location]
    if options[:ts].nil?
        ts = Time.now.to_i
    else
        ts = options[:ts]
    end
    did_info = resolve_did(did, options)
    if did_info.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: cannot resolve DID (on revoking DID)"
            else
                puts '{"error": "cannot resolve DID (on revoking DID)"}'
            end
        end
        exit (-1)
    end
    if did_info["error"] != 0
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: " + did_info["message"].to_s
            else
                puts '{"error": "' + did_info["message"].to_s + '"}'
            end
        end
        exit(1)
    end

    did = did_info["did"]
    did_hash = did.delete_prefix("did:oyd:")
    did10 = did_hash[0,10]
    if doc_location.to_s == ""
        if did_hash.include?(LOCATION_PREFIX)
            hash_split = did_hash.split(LOCATION_PREFIX)
            did_hash = hash_split[0]
            doc_location = hash_split[1]
        end
    end

    # collect relevant information from previous did
    did_old = did.dup
    did10_old = did10.dup
    log_old = did_info["log"]
    privateKey_old = read_private_storage(did10_old + "_private_key.b58")
    revocationKey_old = read_private_storage(did10_old + "_revocation_key.b58")

    if options[:doc_key].nil?
        if options[:doc_pwd].nil?
            privateKey = read_private_key(did10 + "_private_key.b58")
        else
            privateKey = oyd_generate_private_key(options[:doc_pwd].to_s, 'ed25519-priv')
        end
    else
        privateKey = read_private_key(options[:doc_key].to_s)
    end
    if privateKey.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: private key not found"
            else
                puts '{"error": "private key not found"}'
            end
        end
        exit(1)
    end
    if options[:rev_key].nil? && options[:rev_pwd].nil?
        revocationKey = read_private_key(did10 + "_revocation_key.b58")
        revocationLog = read_private_storage(did10 + "_revocation.json")
    else
        if options[:rev_pwd].nil?
            revocationKey = read_private_key(options[:rev_key].to_s)
        else
            revocationKey = oyd_generate_private_key(options[:rev_pwd].to_s, 'ed25519-priv')
        end
        # re-build revocation document
        did_old_doc = did_info["doc"]["doc"]
        ts_old = did_info["log"].last["ts"]
        publicKey_old = oyd_public_key(privateKey_old)
        pubRevoKey_old = oyd_public_key(revocationKey_old)
        did_key_old = publicKey_old + ":" + pubRevoKey_old
        subDid = {"doc": did_old_doc, "key": did_key_old}.to_json
        subDidHash = oyd_hash(subDid)
        signedSubDidHash = oyd_sign(subDidHash, revocationKey)
        revocationLog = { 
            "ts": ts_old,
            "op": 1, # REVOKE
            "doc": subDidHash,
            "sig": signedSubDidHash }.transform_keys(&:to_s).to_json
    end

    if revocationLog.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: private revocation key not found"
            else
                puts '{"error": "private revocation key not found"}'
            end
        end
        exit(1)
    end

    revoc_log = JSON.parse(revocationLog)
    revoc_log["previous"] = [
        oyd_hash(oyd_canonical(log_old[did_info["doc_log_id"].to_i])), 
        oyd_hash(oyd_canonical(log_old[did_info["termination_log_id"].to_i]))
    ]

    if doc_location.to_s == ""
        doc_location = DEFAULT_LOCATION
    end

    # publish revocation log based on location
    case doc_location.to_s
    when /^http/
        retVal = HTTParty.post(doc_location.to_s + "/log/" + did.to_s,
            headers: { 'Content-Type' => 'application/json' },
            body: {"log": revoc_log}.to_json )
        if retVal.code != 200
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Registry Error: " + retVal.parsed_response("error").to_s rescue 
                        puts "Error: invalid response from " + doc_location.to_s + "/log/" + did.to_s
                else
                    puts '{"error": "' + retVal.parsed_response['error'].to_s + '", "source": "registry"}' rescue
                        puts '{"error": "invalid response from ' + doc_location.to_s + "/log/" + did.to_s + '"}'
                end
            end
            exit(1)
        end
    else
        File.write(did10 + ".log", [log_old, revoc_log].flatten.compact.to_json)
        if !did_old.nil?
            File.write(did10_old + ".log", [log_old, revoc_log].flatten.compact.to_json)
        end
    end

    if options[:silent].nil? || !options[:silent]
        # write operations to stdout
        if options[:json].nil? || !options[:json]
            puts "revoked did:oyd:" + did
        else
            puts '{"did": "did:oyd:"' + did.to_s + '", "operation": "revoke"}'
        end
    end
    did

end

def clone_did(did, options)
    # check if locations differ
    target_location = options[:doc_location]
    if target_location.to_s == ""
        target_location = DEFAULT_LOCATION
    end
    if did.include?(LOCATION_PREFIX)
        hash_split = did.split(LOCATION_PREFIX)
        did = hash_split[0]
        source_location = hash_split[1]
    end
    if source_location.to_s == ""
        source_location = DEFAULT_LOCATION
    end
    if target_location == source_location
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: cannot clone to same location (" + target_location.to_s + ")"
            else
                puts '{"error":"Error: cannot clone to same location (' + target_location.to_s + ')"}'
            end
        end
        exit 1
    end

    # get original did info
    options[:doc_location] = source_location
    options[:log_location] = source_location
    source_did = resolve_did(did, options)

    if source_did.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: cannot resolve DID (on cloning DID)"
            else
                puts '{"error": "cannot resolve DID (on cloning DID)"}'
            end
        end
        exit (-1)
    end
    if source_did["error"] != 0
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: " + source_did["message"].to_s
            else
                puts '{"error": "' + source_did["message"].to_s + '"}'
            end
        end
        exit(-1)
    end
    if source_did["doc_log_id"].nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: cannot parse DID log"
            else
                puts '{"error": "cannot parse DID log"}'
            end
        end
        exit(-1)
    end        
    source_log = source_did["log"].first(source_did["doc_log_id"] + 1).last.to_json

    # write did to new location
    options[:doc_location] = target_location
    options[:log_location] = target_location
    options[:previous_clone] = oyd_hash(oyd_canonical(source_log)) + LOCATION_PREFIX + source_location
    options[:source_location] = source_location
    options[:source_did] = source_did["did"]
    write_did([source_did["doc"]["doc"].to_json], nil, "clone", options)

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
    if options[:silent].nil? || !options[:silent]
        puts wd.to_json
    end
end

def sc_init(options)
    sc_info_url = options[:location].to_s + "/api/info"
    sc_info = HTTParty.get(sc_info_url,
        headers: {'Authorization' => 'Bearer ' + options[:token].to_s}).parsed_response rescue {}

    # build DID doc element
    image_hash = sc_info["image_hash"].to_s.delete_prefix("sha256:") rescue ""
    content = {
        "service_endpoint": sc_info["serviceEndPoint"].to_s + "/api/data",
        "image_hash": image_hash,
        "uid": sc_info["uid"]
    }

    # set options and write DID
    sc_options = options.dup
    sc_options[:location] = sc_info["serviceEndPoint"] || options[:location]
    sc_options[:doc_location] = sc_options[:location]
    sc_options[:log_location] = sc_options[:location]
    sc_options[:silent] = true
    did = write_did([content.to_json], nil, "create", sc_options)

    did_info = resolve_did(did, options)
    doc_pub_key = did_info["doc"]["key"].split(":")[0].to_s rescue ""

    # create OAuth App for DID in Semantic Container
    response = HTTParty.post(options[:location].to_s + "/oauth/applications",
        headers: { 'Content-Type'  => 'application/json',
                   'Authorization' => 'Bearer ' + options[:token].to_s },
        body: { name: doc_pub_key, 
                scopes: "admin write read" }.to_json )

    # print DID
    if options[:silent].nil? || !options[:silent]
        retVal = {"did": did}.to_json
        puts retVal
    end

end

def sc_token(did, options)
    if options[:doc_key].nil?
        if options[:doc_pwd].nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: private key not found"
                else
                    puts '{"error": "private key not found"}'
                end
            end
            exit 1
        else
            privateKey = oyd_generate_private_key(options[:doc_pwd].to_s, 'ed25519-priv')
        end
    else
        privateKey = read_private_key(options[:doc_key].to_s)
        if privateKey.nil?
            if options[:silent].nil? || !options[:silent]
                if options[:json].nil? || !options[:json]
                    puts "Error: private key not found"
                else
                    puts '{"error": "private key not found"}'
                end
            end
            exit 1
        end
    end
    if did.include?(LOCATION_PREFIX)
        hash_split = did.split(LOCATION_PREFIX)
        doc_location = hash_split[1]
    end

    # check if provided private key matches pubkey in DID document
    did_info = resolve_did(did, options)
    if did_info["doc"]["key"].split(":")[0].to_s != oyd_public_key(privateKey)
        if options[:silent].nil? || !options[:silent]
            puts "Error: private key does not match DID document"
            if options[:json].nil? || !options[:json]
                puts "Error: private key does not match DID document"
            else
                puts '{"error": "private key does not match DID document"}'
            end
        end
        exit 1
    end

    # authenticate against container
    init_url = doc_location + "/api/oydid/init"
    sid = SecureRandom.hex(20).to_s

    response = HTTParty.post(init_url,
        headers: { 'Content-Type' => 'application/json' },
        body: { "session_id": sid, 
                "public_key": oyd_public_key(privateKey) }.to_json ).parsed_response rescue {}
    if response["challenge"].nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: invalid container authentication"
            else
                puts '{"error": "invalid container authentication"}'
            end
        end
        exit 1
    end
    challenge = response["challenge"].to_s

    # sign challenge and request token
    token_url = doc_location + "/api/oydid/token"
    response = HTTParty.post(token_url,
        headers: { 'Content-Type' => 'application/json' },
        body: { "session_id": sid, 
                "signed_challenge": oyd_sign(challenge, privateKey) }.to_json).parsed_response rescue {}
    puts response.to_json

end

def sc_create(content, did, options)
    # validation
    c = JSON.parse(content.join("")) rescue {}
    if c["service_endpoint"].nil?
        if options[:json].nil? || !options[:json]
            puts "Error: missing service endpoint"
        else
            puts '{"error": "missing service endpoint"}'
        end
        exit 1
    end
    if c["scope"].nil?
        if options[:json].nil? || !options[:json]
            puts "Error: missing scope"
        else
            puts '{"error": "missing scope"}'
        end
        exit 1
    end

    # get Semantic Container location from DID
    did_info = resolve_did(did, options)
    sc_url = did_info["doc"]["doc"]["service_endpoint"]
    baseurl = URI.join(sc_url, "/").to_s.delete_suffix("/")

    sc_options = options.dup
    sc_options[:location] = baseurl
    sc_options[:doc_location] = sc_options[:location]
    sc_options[:log_location] = sc_options[:location]
    sc_options[:silent] = true
    new_did = write_did([c.to_json], nil, "create", sc_options)
    did_info = resolve_did(new_did, sc_options)
    doc_pub_key = did_info["doc"]["key"].split(":")[0].to_s rescue ""

    # create OAuth App for DID in Semantic Container
    response = HTTParty.post(sc_options[:location].to_s + "/oauth/applications",
        headers: { 'Content-Type'  => 'application/json',
                   'Authorization' => 'Bearer ' + options[:token].to_s },
        body: { name: doc_pub_key, 
                scopes: c["scope"],
                query: c["service_endpoint"] }.to_json )

    # !!! add error handling (e.g., for missing token)

    # print DID
    if options[:silent].nil? || !options[:silent]
        retVal = {"did": new_did}.to_json
        puts retVal
    end

end

def print_version()
    puts VERSION
end

def print_help()
    puts "oydid - manage DIDs using the oyd:did method [version " + VERSION + "]"
    puts ""
    puts "Usage: oydid [OPERATION] [OPTION]"
    puts ""
    puts "OPERATION"
    puts "  create    - new DID, reads doc from STDIN"
    puts "  read      - output DID Document for given DID in option"
    puts "  update    - update DID Document, reads doc from STDIN and DID specified"
    puts "              as option"
    puts "  revoke    - revoke DID by publishing revocation entry"
    puts "  delete    - remove DID and all associated records (only for testing)"
    puts "  log       - print relevant log for given DID or log entry hash"
    puts "  logs      - print all available log entries for given DID or log hash"
    puts "  dag       - print graph for given DID"
    puts "  clone     - clone DID to new location"
    puts "  delegate  - add log entry with additional keys for validating signatures"
    puts "              of document or revocation entries"
    puts "  challenge - publish challenge for given DID and revoke specified as"
    puts "              options"
    puts "  confirm   - confirm specified clones or delegates for given DID"
    puts ""
    puts "Semantic Container operations:"
    puts "  sc_init   - create initial DID for a Semantic Container "
    puts "              (requires TOKEN with admin scope)"
    puts "  sc_token  - retrieve OAuth2 bearer token using DID Auth"
    puts "  sc_create - create additional DID for specified subset of data and"
    puts "              scope"
    puts ""
    puts "OPTIONS"
    puts "     --doc-key DOCUMENT-KEY        - filename with Multibase encoded "
    puts "                                     private key for signing documents"
    puts "     --doc-pwd DOCUMENT-PASSWORD   - password for private key for "
    puts "                                     signing documents"
    puts " -h, --help                        - dispay this help text"
    puts "     --json-output                 - write response as JSON object"
    puts " -l, --location LOCATION           - default URL to store/query DID data"
    puts "     --rev-key REVOCATION-KEY      - filename with Multibase encoded "
    puts "                                     private key for signing a revocation"
    puts "     --rev-pwd REVOCATION-PASSWORD - password for private key for signing"
    puts "                                     a revocation"
    puts "     --show-hash                   - for log operation: additionally show"
    puts "                                     hash value of each entry"
    puts "     --show-verification           - display raw data and steps for"
    puts "                                     verifying DID resolution process"
    puts "     --silent                      - suppress any output"
    puts "     --timestamp TIMESTAMP         - timestamp in UNIX epoch to be used"
    puts "                                     (only for testing)"
    puts " -t, --token TOKEN                 - OAuth2 bearer token to access "
    puts "                                     Semantic Container"
    puts "     --trace                       - display trace/debug information when"
    puts "                                     processing request"
    puts " -v, --version                     - display version number"
    puts "     --w3c-did                     - display DID Document in W3C conform"
    puts "                                     format"
end

# commandline options
options = { }
opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: #{$0} OPERATION [OPTIONS]"
  opt.separator  ""
  opt.separator  "OPERATION"
  opt.separator  "OPTIONS"

  options[:log_complete] = false
  options[:show_hash] = false
  options[:show_verification] = false
  opt.on("-l","--location LOCATION","default URL to store/query DID data") do |loc|
    options[:location] = loc
  end
  opt.on("-t","--trace","show trace information when reading DID") do |trc|
    options[:trace] = true
  end
  opt.on("--silent") do |s|
    options[:silent] = true
  end
  opt.on("--show-hash") do |s|
    options[:show_hash] = true
  end
  opt.on("--show-verification") do |s|
    options[:show_verification] = true
  end
  opt.on("--w3c-did") do |w3c|
    options[:w3cdid] = true
  end
  opt.on("--json-output") do |j|
    options[:json] = true
  end
  opt.on("--doc-key DOCUMENT-KEY") do |dk|
    options[:doc_key] = dk
  end
  opt.on("--rev-key REVOCATION-KEY") do |rk|
    options[:rev_key] = rk
  end
  opt.on("--doc-pwd DOCUMENT-PASSWORD") do |dp|
    options[:doc_pwd] = dp
  end
  opt.on("--rev-pwd REVOCATION-PASSWORD") do |rp|
    options[:rev_pwd] = rp
  end
  opt.on("-t", "--token TOKEN", "token to access Semantic Container") do |t|
    options[:token] = t
  end
  opt.on("--ts TIMESTAMP") do |ts|
    options[:ts] = ts.to_i
  end
  opt.on("-h", "--help") do |h|
    print_help()
    exit(0)
  end
  opt.on("-v", "--version") do |h|
    print_version()
    exit(0)
  end
end
opt_parser.parse!

operation = ARGV.shift rescue ""
input_did = ARGV.shift rescue ""
if input_did.to_s == "" && operation.to_s.start_with?("did:oyd:")
    input_did = operation
    operation = "read"
end

if operation == "create" || operation == "sc_create" || operation == "update" 
    content = []
    ARGF.each_line { |line| content << line }
end

if options[:doc_location].nil?
    options[:doc_location] = options[:location]
end
if options[:log_location].nil?
    options[:log_location] = options[:location]
end

case operation.to_s
when "create"
    write_did(content, nil, "create", options)
when "read"
    result = resolve_did(input_did, options)
    if result.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: cannot resolve DID (on reading DID)"
            else
                puts '{"error": "cannot resolve DID (on reading DID)"}'
            end
        end
        exit (-1)
    end
    if result["error"] != 0
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: " + result["message"].to_s
            else
                puts '{"error": "' + result["message"].to_s + '"}'
            end
        end
        exit(-1)
    end
    if !options[:trace]
        if options[:w3cdid]
            w3c_did(result, options)
        else
            if (options[:silent].nil? || !options[:silent])
                if  options[:show_verification]
                    puts "=== end of verification output ==="
                    puts ""
                end
                puts result["doc"].to_json
            end
        end
    end
when "clone"
    result = clone_did(input_did, options)
    if result.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: cannot resolve DID (after cloning DID)"
            else
                puts '{"error": "cannot resolve DID (after cloning DID)"}'
            end
        end
        exit (-1)
    end
when "log", "logs"
    if operation.to_s == "logs"
        options[:log_complete] = true
    end
    log_hash = input_did
    result = resolve_did(input_did, options)
    if result.nil?
        if options[:log_location].nil?
            if input_did.include?(LOCATION_PREFIX)
                retVal = input_did.split(LOCATION_PREFIX)
                log_hash = retVal[0]
                log_location = retVal[1]
            end
        else
            log_location = options[:log_location]
        end
        if log_location.to_s == ""
            log_location = DEFAULT_LOCATION
        end
        if !(log_location == "" || log_location == "local")
            if !log_location.start_with?("http")
                log_location = "https://" + log_location
            end
        end
        result = HTTParty.get(log_location.to_s + "/log/" + log_hash.to_s)
        if options[:silent].nil? || !options[:silent]
            result = JSON.parse(result.to_s)
            if options[:show_hash]
                result = add_hash(result)
            end
            puts result.to_json
        end
    else
        if options[:silent].nil? || !options[:silent]
            result = result["log"]
            if options[:show_hash]
                result = add_hash(result)
            end
            puts result.to_json
        end
    end
when "dag"
    options[:trace] = true
    result = resolve_did(input_did, options)
    if result.nil?
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: cannot resolve DID (on writing DAG)"
            else
                puts '{"error": "cannot resolve DID (on writing DAG)"}'
            end
        end
        exit (-1)
    end
    if result["error"] != 0
        if options[:silent].nil? || !options[:silent]
            if options[:json].nil? || !options[:json]
                puts "Error: " + result["message"].to_s
            else
                puts '{"error": "' + result["message"].to_s + '"}'
            end
        end
        exit(-1)
    end
when "update"
    write_did(content, input_did, "update", options)
when "revoke"
    revoke_did(input_did, options)
when "delete"
    delete_did(input_did, options)

when "sc_init"
    sc_init(options)
when "sc_token"
    sc_token(input_did, options)
when "sc_create"
    sc_create(content, input_did, options)

when "delegate", "challenge", "confirm"
    if options[:json].nil? || !options[:json]
        puts "Error: function not yet available"
    else
        puts '{"error": "function not yet available"}'
    end
else
    print_help()
end
