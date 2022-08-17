# -*- encoding: utf-8 -*-
# frozen_string_literal: true

require 'dag'
require 'jwt'
require 'rbnacl'
require 'ed25519'
require 'httparty'
require 'multibases'
require 'multihashes'
require 'multicodecs'
require 'json/canonicalization'
require 'oydid/basic'
require 'oydid/log'
require 'oydid/didcomm'

class Oydid

    LOCATION_PREFIX = "@"
    DEFAULT_LOCATION = "https://oydid.ownyourdata.eu"


    # expected DID format: did:oyd:123
    def self.read(did, options)
        # setup
        currentDID = {
            "did": did,
            "doc": "",
            "log": [],
            "doc_log_id": nil,
            "termination_log_id": nil,
            "error": 0,
            "message": "",
            "verification": ""
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
        if did_document.first.nil?
            return [nil, did_document.last]
        end
        did_document = did_document.first
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
        log_array, msg = retrieve_log(log_hash, did10 + ".log", log_location, options)
        if log_array.nil?
            return [nil, msg]
        else
            if options[:trace]
                puts " .. Log retrieved"
            end
            dag, create_index, terminate_index, msg = dag_did(log_array, options)
            if dag.nil?
                return [nil, msg]
            end
            if options[:trace]
                puts " .. DAG with " + dag.vertices.length.to_s + " vertices and " + dag.edges.length.to_s + " edges, CREATE index: " + create_index.to_s
            end
            ordered_log_array = dag2array(dag, log_array, create_index, [], options)
            ordered_log_array << log_array[terminate_index]
            currentDID["log"] = ordered_log_array
            if options[:trace]
                if options[:silent].nil? || !options[:silent]
                    puts "    vertex " + terminate_index.to_s + " at " + log_array[terminate_index]["ts"].to_s + " op: " + log_array[terminate_index]["op"].to_s + " doc: " + log_array[terminate_index]["doc"].to_s
                end
            end
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

            return [currentDID, ""]
        end

    end

    def self.create(content, options)
        return write(content, nil, "create", options)
    end

    def self.update(content, did, options)
        return write(content, did, "update", options)
    end

    def self.generate_base(content, did, mode, options)
        # input validation
        did_doc = JSON.parse(content.to_json) rescue nil
        if did_doc.nil?
            return [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "invalid payload"]
        end        
        did_old = nil
        log_old = nil
        prev_hash = []
        revoc_log = nil
        doc_location = options[:location]
        if options[:ts].nil?
            ts = Time.now.to_i
        else
            ts = options[:ts]
        end

        if mode == "create" || mode == "clone"
            operation_mode = 2 # CREATE
            if options[:doc_key].nil?
                if options[:doc_enc].nil?
                    privateKey, msg = generate_private_key(options[:doc_pwd].to_s, 'ed25519-priv')
                else
                    privateKey, msg = decode_private_key(options[:doc_enc].to_s)
                end
            else
                privateKey, msg = read_private_key(options[:doc_key].to_s)
                if privateKey.nil?
                    return [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "private document key not found"]
                end
            end
            if options[:rev_key].nil?
                if options[:rev_enc].nil?
                    revocationKey, msg = generate_private_key(options[:rev_pwd].to_s, 'ed25519-priv')
                else
                    revocationKey, msg = decode_private_key(options[:rev_enc].to_s)
                end
            else
                revocationKey, msg = read_private_key(options[:rev_key].to_s)
                if revocationKey.nil?
                    return [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "private revocation key not found"]
                end
            end
        else # mode == "update"  => read information
            did_info, msg = read(did, options)
            if did_info.nil?
                return [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "cannot resolve DID (on updating DID)"]
            end
            if did_info["error"] != 0
                return [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, did_info["message"].to_s]
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
            if options[:old_doc_key].nil?
                if options[:old_doc_enc].nil?
                    if options[:old_doc_pwd].nil?
                        privateKey_old = read_private_storage(did10_old + "_private_key.b58")
                    else
                        privateKey_old, msg = generate_private_key(options[:old_doc_pwd].to_s, 'ed25519-priv')
                    end
                else
                    privateKey_old, msg = decode_private_key(options[:old_doc_enc].to_s)
                end
            else
                privateKey_old, msg = read_private_key(options[:old_doc_key].to_s)
            end
            if privateKey_old.nil?
                return [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "invalid or missing old private document key"]
            end
            if options[:old_rev_key].nil?
                if options[:old_rev_enc].nil?
                    if options[:old_rev_pwd].nil?
                        revocationKey_old = read_private_storage(did10_old + "_revocation_key.b58")
                    else
                        revocationKey_old, msg = generate_private_key(options[:old_rev_pwd].to_s, 'ed25519-priv')
                    end
                else
                    revocationKey_old, msg = decode_private_key(options[:old_rev_enc].to_s)
                end
            else
                revocationKey_old, msg = read_private_key(options[:old_rev_key].to_s)
            end
            if revocationKey_old.nil?
                return [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "invalid or missing old private revocation key"]
            end

            # key management
            if options[:doc_key].nil?
                if options[:doc_enc].nil?
                    privateKey, msg = generate_private_key(options[:doc_pwd].to_s, 'ed25519-priv')
                else
                    privateKey, msg = decode_private_key(options[:doc_enc].to_s)
                end
            else
                privateKey, msg = read_private_key(options[:doc_key].to_s)
            end
            # if options[:rev_key].nil? && options[:rev_pwd].nil? && options[:rev_enc].nil?
            #     revocationLog = read_private_storage(did10 + "_revocation.json")
            #     if revocationLog.nil?
            #         return [nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, "invalid or missing old revocation log"]
            #     end
            # else
                if options[:rev_key].nil?
                    if options[:rev_enc].nil?
                        if options[:rev_pwd].nil?
                            revocationKey, msg = generate_private_key("", 'ed25519-priv')
                        else
                            revocationKey, msg = generate_private_key(options[:rev_pwd].to_s, 'ed25519-priv')
                        end
                    else
                        revocationKey, msg = decode_private_key(options[:rev_enc].to_s)
                    end
                else
                    revocationKey, msg = read_private_key(options[:rev_key].to_s)
                end

                # re-build revocation document
                did_old_doc = did_info["doc"]["doc"]
                ts_old = did_info["log"].last["ts"]
                publicKey_old = public_key(privateKey_old).first
                pubRevoKey_old = public_key(revocationKey_old).first
                did_key_old = publicKey_old + ":" + pubRevoKey_old
                subDid = {"doc": did_old_doc, "key": did_key_old}.to_json
                subDidHash = hash(canonical(subDid))
                signedSubDidHash = sign(subDidHash, revocationKey_old).first
                revocationLog = { 
                    "ts": ts_old,
                    "op": 1, # REVOKE
                    "doc": subDidHash,
                    "sig": signedSubDidHash }.transform_keys(&:to_s).to_json
            # end
            revoc_log = JSON.parse(revocationLog)
            revoc_log["previous"] = [
                hash(canonical(log_old[did_info["doc_log_id"].to_i])), 
                hash(canonical(log_old[did_info["termination_log_id"].to_i]))
            ]
            prev_hash = [hash(canonical(revoc_log))]
        end

        publicKey = public_key(privateKey).first
        pubRevoKey = public_key(revocationKey).first
        did_key = publicKey + ":" + pubRevoKey

        # build new revocation document
        subDid = {"doc": did_doc, "key": did_key}.to_json
        subDidHash = hash(canonical(subDid))
        signedSubDidHash = sign(subDidHash, revocationKey).first
        r1 = { "ts": ts,
               "op": 1, # REVOKE
               "doc": subDidHash,
               "sig": signedSubDidHash }.transform_keys(&:to_s)

        # build termination log entry
        l2_doc = hash(canonical(r1))
        if !doc_location.nil?
            l2_doc += LOCATION_PREFIX + doc_location.to_s
        end
        l2 = { "ts": ts,
               "op": 0, # TERMINATE
               "doc": l2_doc,
               "sig": sign(l2_doc, privateKey).first,
               "previous": [] }.transform_keys(&:to_s)

        # build actual DID document
        log_str = hash(canonical(l2))
        if !doc_location.nil?
            log_str += LOCATION_PREFIX + doc_location.to_s
        end
        didDocument = { "doc": did_doc,
                        "key": did_key,
                        "log": log_str }.transform_keys(&:to_s)

        # create DID
        l1_doc = hash(canonical(didDocument))
        if !doc_location.nil?
            l1_doc += LOCATION_PREFIX + doc_location.to_s
        end    
        did = "did:oyd:" + l1_doc
        did10 = l1_doc[0,10]

        if mode == "clone"
            # create log entry for source DID
            new_log = {
                "ts": ts,
                "op": 4, # CLONE
                "doc": l1_doc,
                "sig": sign(l1_doc, privateKey).first,
                "previous": [options[:previous_clone].to_s]
            }
            retVal = HTTParty.post(options[:source_location] + "/log/" + options[:source_did],
                headers: { 'Content-Type' => 'application/json' },
                body: {"log": new_log}.to_json )
            prev_hash = [hash(canonical(new_log))]
        end

        # build creation log entry
        if operation_mode == 3 # UPDATE
            l1 = { "ts": ts,
                   "op": operation_mode, # UPDATE
                   "doc": l1_doc,
                   "sig": sign(l1_doc, privateKey_old).first,
                   "previous": prev_hash }.transform_keys(&:to_s)
        else        
            l1 = { "ts": ts,
                   "op": operation_mode, # CREATE
                   "doc": l1_doc,
                   "sig": sign(l1_doc, privateKey).first,
                   "previous": prev_hash }.transform_keys(&:to_s)
        end

        return [did, didDocument, revoc_log, l1, l2, r1, privateKey, revocationKey, did_old, log_old, ""]
    end

    def self.publish(did, didDocument, logs, options)
        did_hash = did.delete_prefix("did:oyd:")
        did10 = did_hash[0,10]

        doc_location = options[:doc_location]
        if doc_location.to_s == ""
            if did_hash.include?(LOCATION_PREFIX)
                hash_split = did_hash.split(LOCATION_PREFIX)
                did_hash = hash_split[0]
                doc_location = hash_split[1]
            else
                doc_location = DEFAULT_LOCATION
            end
        end

        # wirte data based on location
        case doc_location.to_s
        when /^http/
            # build object to post
            did_data = {
                "did": did,
                "did-document": didDocument,
                "logs": logs
            }
            oydid_url = doc_location.to_s + "/doc"
            retVal = HTTParty.post(oydid_url,
                headers: { 'Content-Type' => 'application/json' },
                body: did_data.to_json )
            if retVal.code != 200
                err_msg = retVal.parsed_response("error").to_s rescue "invalid response from " + doc_location.to_s + "/doc"
                return [false, err_msg]
            end
        else
            # write files to disk
            write_private_storage(logs.to_json, did10 + ".log")
            write_private_storage(didDocument.to_json, did10 + ".doc")
            write_private_storage(did, did10 + ".did")
        end
        return [true, ""]

    end

    def self.write(content, did, mode, options)
        did, didDocument, revoc_log, l1, l2, r1, privateKey, revocationKey, did_old, log_old, msg = generate_base(content, did, mode, options)
        if msg != ""
            return [nil, msg]
        end

        did_hash = did.delete_prefix("did:oyd:")
        did10 = did_hash[0,10]
        did_old_hash = did_old.delete_prefix("did:oyd:") rescue nil
        did10_old = did_old_hash[0,10] rescue nil

        doc_location = options[:doc_location]
        if doc_location.to_s == ""
            if did_hash.include?(LOCATION_PREFIX)
                hash_split = did_hash.split(LOCATION_PREFIX)
                did_hash = hash_split[0]
                doc_location = hash_split[1]
            else
                doc_location = DEFAULT_LOCATION
            end
        end

        case doc_location.to_s
        when /^http/
            logs = [revoc_log, l1, l2].flatten.compact
        else
            logs = [log_old, revoc_log, l1, l2].flatten.compact
            if !did_old.nil?
                write_private_storage([log_old, revoc_log, l1, l2].flatten.compact.to_json, did10_old + ".log")
            end
        end
        success, msg = publish(did, didDocument, logs, options)

        if success
            w3c_input = {
                "did" => did,
                "doc" => didDocument
            }
            retVal = {
                "did" => did,
                "doc" => didDocument,
                "doc_w3c" => w3c(w3c_input, options),
                "log" => logs
            }
            if options[:return_secrets]
                retVal["private_key"] = privateKey
                retVal["revocation_key"] = revocationKey
                retVal["revocation_log"] = r1
            else
                write_private_storage(privateKey, did10 + "_private_key.b58")
                write_private_storage(revocationKey, did10 + "_revocation_key.b58")
                write_private_storage(r1.to_json, did10 + "_revocation.json")
            end

            return [retVal, ""]
        else
            return [nil, msg]
        end
    end

    def self.revoke_base(did, options)
        did_orig = did.dup
        doc_location = options[:doc_location]
        if options[:ts].nil?
            ts = Time.now.to_i
        else
            ts = options[:ts]
        end
        did_info, msg = read(did, options)
        if did_info.nil?
            return [nil, "cannot resolve DID (on revoking DID)"]
        end
        if did_info["error"] != 0
            return [nil, did_info["message"].to_s]
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

        if options[:old_doc_key].nil?
            if options[:old_doc_enc].nil?
                if options[:old_doc_pwd].nil?
                    privateKey_old = read_private_storage(did10_old + "_private_key.b58")
                else
                    privateKey_old, msg = generate_private_key(options[:old_doc_pwd].to_s, 'ed25519-priv')
                end
            else
                privateKey_old, msg = decode_private_key(options[:old_doc_enc].to_s)
            end
        else
            privateKey_old, msg = read_private_key(options[:old_doc_key].to_s)
        end
        if privateKey_old.nil?
            return [nil, "invalid or missing old private document key"]
        end
        if options[:old_rev_key].nil?
            if options[:old_rev_enc].nil?
                if options[:old_rev_pwd].nil?
                    revocationKey_old = read_private_storage(did10_old + "_revocation_key.b58")
                else
                    revocationKey_old, msg = generate_private_key(options[:old_rev_pwd].to_s, 'ed25519-priv')
                end
            else
                revocationKey_old, msg = decode_private_key(options[:old_rev_enc].to_s)
            end
        else
            revocationKey_old, msg = read_private_key(options[:old_rev_key].to_s)
        end
        if revocationKey_old.nil?
            return [nil, "invalid or missing old private revocation key"]
        end

        if options[:rev_key].nil? && options[:rev_pwd].nil? && options[:rev_enc].nil?
            revocationKey, msg = read_private_key(did10 + "_revocation_key.b58")
            revocationLog = read_private_storage(did10 + "_revocation.json")
        else
            if options[:rev_pwd].nil?
                if options[:rev_enc].nil?
                    revocationKey, msg = read_private_key(options[:rev_key].to_s)
                else
                    revocationKey, msg = decode_private_key(options[:rev_enc].to_s)
                end
            else
                revocationKey, msg = generate_private_key(options[:rev_pwd].to_s, 'ed25519-priv')
            end
            # re-build revocation document
            did_old_doc = did_info["doc"]["doc"]
            ts_old = did_info["log"].last["ts"]
            publicKey_old = public_key(privateKey_old).first
            pubRevoKey_old = public_key(revocationKey_old).first
            did_key_old = publicKey_old + ":" + pubRevoKey_old
            subDid = {"doc": did_old_doc, "key": did_key_old}.to_json
            subDidHash = hash(canonical(subDid))
            signedSubDidHash = sign(subDidHash, revocationKey_old).first
            revocationLog = { 
                "ts": ts_old,
                "op": 1, # REVOKE
                "doc": subDidHash,
                "sig": signedSubDidHash }.transform_keys(&:to_s).to_json
        end

        if revocationLog.nil?
            return [nil, "private revocation key not found"]
        end

        revoc_log = JSON.parse(revocationLog)
        revoc_log["previous"] = [
            hash(canonical(log_old[did_info["doc_log_id"].to_i])), 
            hash(canonical(log_old[did_info["termination_log_id"].to_i]))
        ]
        return [revoc_log, ""]
    end

    def self.revoke_publish(did, revoc_log, options)
        did_hash = did.delete_prefix("did:oyd:")
        did10 = did_hash[0,10]
        doc_location = options[:doc_location]
        if did_hash.include?(LOCATION_PREFIX)
            hash_split = did_hash.split(LOCATION_PREFIX)
            did_hash = hash_split[0]
            doc_location = hash_split[1]
        end
        if doc_location.to_s == ""
            doc_location = DEFAULT_LOCATION
        end

        # publish revocation log based on location
        case doc_location.to_s
        when /^http/
            retVal = HTTParty.post(doc_location.to_s + "/log/" + did_hash.to_s,
                headers: { 'Content-Type' => 'application/json' },
                body: {"log": revoc_log}.to_json )
            if retVal.code != 200
                msg = retVal.parsed_response("error").to_s rescue "invalid response from " + doc_location.to_s + "/log/" + did_hash.to_s
                return [nil, msg]
            end
        else
            File.write(did10 + ".log", revoc_log.to_json)
            if !did_old.nil?
                File.write(did10_old + ".log", revoc_log.to_json)
            end
        end

        return [did, ""]
    end

    def self.revoke(did, options)
        revoc_log, msg = revoke_base(did, options)
        if revoc_log.nil?
            return [nil, msg]
        end
        success, msg = revoke_publish(did, revoc_log, options)
    end

    def self.clone(did, options)
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
            return [nil, "cannot clone to same location (" + target_location.to_s + ")"]
        end

        # get original did info
        options[:doc_location] = source_location
        options[:log_location] = source_location
        source_did, msg = read(did, options)
        if source_did.nil?
            return [nil, "cannot resolve DID (on cloning DID)"]
        end
        if source_did["error"] != 0
            return [nil, source_did["message"].to_s]
        end
        if source_did["doc_log_id"].nil?
            return [nil, "cannot parse DID log"]
        end        
        source_log = source_did["log"].first(source_did["doc_log_id"] + 1).last.to_json

        # write did to new location
        options[:doc_location] = target_location
        options[:log_location] = target_location
        options[:previous_clone] = hash(canonical(source_log)) + LOCATION_PREFIX + source_location
        options[:source_location] = source_location
        options[:source_did] = source_did["did"]
        retVal, msg = write(source_did["doc"]["doc"], nil, "clone", options)
        return [retVal, msg]
    end

   def self.w3c(did_info, options)
        did = did_info["did"]
        if !did.start_with?("did:oyd:")
            did = "did:oyd:" + did
        end

        didDoc = did_info.transform_keys(&:to_s)["doc"]
        pubDocKey = didDoc["key"].split(":")[0] rescue ""
        pubRevKey = didDoc["key"].split(":")[1] rescue ""

        wd = {}
        wd["@context"] = "https://www.w3.org/ns/did/v1"
        wd["id"] = did
        wd["verificationMethod"] = [{
            "id": did + "#key-doc",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": pubDocKey
        },{
            "id": did + "#key-rev",
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": pubRevKey
        }]

        if didDoc["@context"].to_s == "https://www.w3.org/ns/did/v1"
            didDoc.delete("@context")
        end
        if didDoc["doc"].to_s != ""
            didDoc = didDoc["doc"]
        end
        newDidDoc = []
        if didDoc.is_a?(Hash)
            if didDoc["authentication"].to_s != ""
                wd["authentication"] = didDoc["authentication"]
                didDoc.delete("authentication")
            end
            if didDoc["service"].to_s != ""
                if didDoc["service"].is_a?(Array)
                    newDidDoc = didDoc.dup
                    newDidDoc.delete("service")
                    if newDidDoc == {}
                        newDidDoc = []
                    else
                        if !newDidDoc.is_a?(Array)
                            newDidDoc=[newDidDoc]
                        end
                    end
                    newDidDoc << didDoc["service"]
                    newDidDoc = newDidDoc.flatten
                else
                    newDidDoc = didDoc["service"]
                end
            else
                newDidDoc = didDoc
            end
        else
            newDidDoc = didDoc
        end
        wd["service"] = newDidDoc
        return wd
    end

    def self.fromW3C(didDocument, options)
        didDocument = didDocument.transform_keys(&:to_s)
        if didDocument["@context"].to_s == "https://www.w3.org/ns/did/v1"
            didDocument.delete("@context")
        end
        didDocument
    end

end