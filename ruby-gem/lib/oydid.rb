# -*- encoding: utf-8 -*-
# frozen_string_literal: true

require 'jwt'
require 'rdf'
require 'rdf/normalize'
require 'json'
require 'json/ld'
require 'rbnacl'
require 'ed25519'
require 'openssl'
require 'httparty'
require 'multibases'
require 'multicodecs'
require 'simple_dag'
require 'json/canonicalization'
require 'oydid/basic'
require 'oydid/log'
require 'oydid/didcomm'
require 'oydid/vc'

class Oydid

    LOCATION_PREFIX = "@"
    DEFAULT_LOCATION = "https://oydid.ownyourdata.eu"
    DEFAULT_DIGEST = "sha2-256"
    SUPPORTED_DIGESTS = ["sha2-256", "sha2-512", "sha3-224", "sha3-256", "sha3-384", "sha3-512", "blake2b-16", "blake2b-32", "blake2b-64"]
    DEFAULT_ENCODING = "base58btc"
    SUPPORTED_ENCODINGS = ["base16", "base32", "base58btc", "base64"]
    LOG_HASH_OPTIONS = {:digest => "sha2-256", :encode => "base58btc"}
    ED25519_SECURITY_SUITE = "https://w3id.org/security/suites/ed25519-2020/v1"
    JWS_SECURITY_SUITE = "https://w3id.org/security/suites/jws-2020/v1"
    DEFAULT_PUBLIC_RESOLVER = "https://dev.uniresolver.io/1.0/identifiers/"

    # full Multicodecs table: https://github.com/multiformats/multicodec/blob/master/table.csv
    # Multicodecs.register(code: 0x1305, name: 'rsa-priv', tag: 'key')
    # Multicodecs.register(code: 0x1205, name: 'rsa-pub', tag: 'key')

    # expected DID format: did:oyd:123
    def self.read(did, options)
        if did.to_s == ""
            return [nil, "missing DID"]
        end

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
            if did.include?(CGI.escape LOCATION_PREFIX)
                tmp = did.split(CGI.escape LOCATION_PREFIX)
                did = tmp[0] 
                did_location = tmp[1]
            end
        end
        if did_location == ""
            did_location = DEFAULT_LOCATION
        end
        did_hash = did.delete_prefix("did:oyd:")
        did10 = did_hash[0,10]

        # retrieve DID document
        did_document = retrieve_document(did_hash, did10 +  ".doc", did_location, options)
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

            result = dag2array(dag, log_array, create_index, [], options)
            ordered_log_array = dag2array_terminate(dag, log_array, terminate_index, result, options)
            currentDID["log"] = ordered_log_array
            # !!! ugly hack to get access to all delegation keys required in dag_update
            currentDID["full_log"] = log_array
            if options[:trace]
                if options[:silent].nil? || !options[:silent]
                    dag.edges.each do |e|
                        puts "    edge " + e.origin[:id].to_s + " <- " + e.destination[:id].to_s
                    end
                end
            end

            # identify if DID Rotation was performed
            rotated_DID = (currentDID.transform_keys(&:to_s)["doc"]["doc"].has_key?("@context") &&
                currentDID.transform_keys(&:to_s)["doc"]["doc"].has_key?("id") &&
                currentDID.transform_keys(&:to_s)["doc"]["doc"]["id"].split(":").first == "did") rescue false

            if rotated_DID
                doc = currentDID["doc"].dup
                currentDID = dag_update(currentDID, options)
                currentDID["doc"] = doc
            else
                currentDID = dag_update(currentDID, options)
            end
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

    def self.simulate_did(content, did, mode, options)
        did_doc, did_key, did_log, msg = generate_base(content, did, mode, options)
        user_did = did_doc[:did]
        return [user_did, msg]
    end

    def self.generate_base(content, did, mode, options)
        # input validation
        did_doc = JSON.parse(content.to_json) rescue nil
        if did_doc.nil?
            if !content.nil?
                return [nil, nil, nil, "invalid payload"]
            end
        end

        did_old = nil
        log_old = nil
        prev_hash = []
        revoc_log = nil
        doc_location = options[:location]
        if options[:ts].nil?
            ts = Time.now.utc.to_i
        else
            ts = options[:ts]
        end

        options[:cmsm2] = false
        if options[:cmsm]
            if did_doc["key"].nil?
                return [nil, nil, nil, "CMSM requires public key"]
            end
            cmsm_keys = did_doc["key"].split(':')
            did_doc.delete("key")
            if did_doc == {}
                did_doc = nil
            end
            if cmsm_keys.count == 1
                publicKey = cmsm_keys.first
                revocationKey, msg = generate_private_key("", options[:key_type]+'-priv', options)
                pubRevoKey = public_key(revocationKey, options).first
            else
                return [nil, nil, nil, "CMSM with multiple keys is not yet supported"]
            end

            # check if information for provided key already exists
            payload, msg = check_cmsm(publicKey, options)
            if !payload.nil? && !did_doc.nil? && !did_doc["opt"].nil?
                if payload.is_a?(String)
                    payload = JSON.parse(payload) rescue nil
                end
                if payload.nil?
                    return [nil, nil, nil, "invalid persisted data in CMSM flow"]
                end
                did_doc = JSON.parse(did_doc.to_json)
                if did_doc["opt"].nil?
                    if options[:sig].nil?
                        return [nil, nil, nil, "1missing signature in CMSM flow (sig)"]
                    end
                    l2_sig = options[:sig]
                else
                    if did_doc["opt"]["sig"].nil?
                        return [nil, nil, nil, "2missing signature in CMSM flow (sig)"]
                    end
                    l2_sig = did_doc["opt"]["sig"]
                end

                options[:cmsm2] = true
                privateKey = nil

                revocationKey = payload["revocationKey"]
                did_doc = payload["did_doc"]
                did_key = payload["did_key"]
                l2_doc = payload["l2_doc"]
                r1 = payload["r1"]
            end
        else
            # key management
            tmp_did_hash = did.delete_prefix("did:oyd:") rescue ""
            tmp_did10 = tmp_did_hash[0,10] + "_private_key.enc" rescue ""
            privateKey, msg = getPrivateKey(options[:doc_enc], options[:doc_pwd], options[:doc_key], tmp_did10, options)
            if privateKey.nil?
                privateKey, msg = generate_private_key("", options[:key_type]+'-priv', options)
                if privateKey.nil?
                    return [nil, nil, nil, "private document key not found"]
                end
            end
            tmp_did10 = tmp_did_hash[0,10] + "_revocation_key.enc" rescue ""
            revocationKey, msg = getPrivateKey(options[:rev_enc], options[:rev_pwd], options[:rev_key], tmp_did10, options)
            if revocationKey.nil?
                revocationKey, msg = generate_private_key("", options[:key_type]+'-priv', options)
                if revocationKey.nil?
                    return [nil, nil, nil, "private revocation key not found"]
                end
            end
        end

        # mode-specific handling
        if mode == "create" || mode == "clone"
            operation_mode = 2 # CREATE

        else # mode == "update"  => read information first
            operation_mode = 3 # UPDATE

            did_info, msg = read(did, options)
            if did_info.nil?
                return [nil, nil, nil, "cannot resolve DID (on updating DID)"]
            end
            if did_info["error"] != 0
                return [nil, nil, nil, did_info["message"].to_s]
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
            did_old = did.dup
            did10_old = did10.dup
            log_old = did_info["log"]

            # check if provided old keys are native DID keys or delegates ==================
            tmp_old_doc_did10 = did10_old + "_private_key.enc" rescue ""
            old_privateKey, msg = getPrivateKey(options[:old_doc_enc], options[:old_doc_pwd], options[:old_doc_key], tmp_old_doc_did10, options)
            tmp_old_rev_did10 = did10_old + "_revocation_key.enc" rescue ""
            old_revocationKey, msg = getPrivateKey(options[:old_rev_enc], options[:old_rev_pwd], options[:old_rev_key], tmp_old_rev_did10, options)
            old_publicDocKey = public_key(old_privateKey, {}).first
            old_publicRevKey = public_key(old_revocationKey, {}).first

            old_did_key = old_publicDocKey + ":" + old_publicRevKey

            # compare old keys with existing DID Document & generate revocation record
            if old_did_key.to_s == did_info["doc"]["key"].to_s
                # provided keys are native DID keys ------------------

                # re-build revocation document
                old_did_doc = did_info["doc"]["doc"]
                old_ts = did_info["log"].last["ts"]
                old_subDid = {"doc": old_did_doc, "key": old_did_key}.to_json
                old_subDidHash = multi_hash(canonical(old_subDid), LOG_HASH_OPTIONS).first
                old_signedSubDidHash = sign(old_subDidHash, old_revocationKey, LOG_HASH_OPTIONS).first
                revocationLog = { 
                    "ts": old_ts,
                    "op": 1, # REVOKE
                    "doc": old_subDidHash,
                    "sig": old_signedSubDidHash }.transform_keys(&:to_s).to_json
            else
                # proviced keys are either delegates or invalid ------
                # * check validity of key-doc delegate
                pubKeys, msg = getDelegatedPubKeysFromDID(did, "doc")
                if !pubKeys.include?(old_publicDocKey)
                    return [nil, nil, nil, "invalid or missing old private document key"]
                end

                # * check validity of key-rev delegate
                pubKeys, msg = getDelegatedPubKeysFromDID(did, "rev")
                if !pubKeys.include?(old_publicRevKey)
                    return [nil, nil, nil, "invalid or missing old private revocation key"]
                end

                # retrieve revocationLog from previous in key-rev delegate
                revoc_log = nil
                log_old.each do |item|
                    if !item["encrypted-revocation-log"].nil?
                        revoc_log = item["encrypted-revocation-log"]
                    end
                end
                if revoc_log.nil?
                    return [nil, nil, nil, "cannot retrieve revocation log"]
                end
                revocationLog, msg = decrypt(revoc_log.to_json, old_revocationKey.to_s)
                if revocationLog.nil?
                    return [nil, nil, nil, "cannot decrypt revocation log entry: " + msg]
                end
            end # compare old keys with existing DID Document

            revoc_log = JSON.parse(revocationLog)
            revoc_log["previous"] = [
                multi_hash(canonical(log_old[did_info["doc_log_id"].to_i]), LOG_HASH_OPTIONS).first, 
                multi_hash(canonical(log_old[did_info["termination_log_id"].to_i]), LOG_HASH_OPTIONS).first
            ]
            prev_hash = [multi_hash(canonical(revoc_log), LOG_HASH_OPTIONS).first]
        end
        if !options[:cmsm2]
            if !options[:cmsm]
                publicKey = public_key(privateKey, options).first
                pubRevoKey = public_key(revocationKey, options).first
            end
            did_key = publicKey + ":" + pubRevoKey

            if options[:keyAgreement]
                if did_doc.nil?
                    did_doc = {}
                end
                did_doc[:keyAgreement] = ["#key-doc"]
                did_doc = did_doc.transform_keys(&:to_s)
            end
            if options[:x25519_keyAgreement]
                if did_doc.nil?
                    did_doc = {}
                end
                did_doc[:keyAgreement] = [{
                    "id": "#key-doc-x25519",
                    "type": "X25519KeyAgreementKey2019",
                    "publicKeyMultibase": public_key(privateKey, options, 'x25519-pub').first
                }]
                did_doc = did_doc.transform_keys(&:to_s)
            end
            if options[:authentication]
                if did_doc.nil?
                    did_doc = {}
                end
                did_doc[:authentication] = ["#key-doc"]
                did_doc = did_doc.transform_keys(&:to_s)
            end

            # build new revocation document
            subDid = {"doc": did_doc, "key": did_key}.to_json
            retVal = multi_hash(canonical(subDid), LOG_HASH_OPTIONS)
            if retVal.first.nil?
                return [nil, nil, nil, retVal.last]
            end
            subDidHash = retVal.first
            signedSubDidHash = sign(subDidHash, revocationKey, LOG_HASH_OPTIONS).first
            r1 = { "ts": ts,
                   "op": 1, # REVOKE
                   "doc": subDidHash,
                   "sig": signedSubDidHash }.transform_keys(&:to_s)

            # build termination log entry
            l2_doc = multi_hash(canonical(r1), LOG_HASH_OPTIONS).first
            if !doc_location.nil?
                l2_doc += LOCATION_PREFIX + doc_location.to_s
            end

            if options[:cmsm]
                # persist data
                payload = {
                    revocationKey: revocationKey,
                    did_doc: did_doc,
                    did_key: did_key,
                    l2_doc: l2_doc,
                    r1: r1
                }
                success, msg = persist_cmsm(publicKey, payload, options)

                cmsm_doc = {
                    cmsm: true,
                    pk: publicKey,
                    sign: l2_doc
                }
                return [cmsm_doc, nil, r1, "cmsm"]
            end
            l2_sig = sign(l2_doc, privateKey, options).first
        end

        if options[:confirm_logs].nil?
            previous_array = []
        else
            previous_array = options[:confirm_logs]
        end
        l2 = { "ts": ts,
               "op": 0, # TERMINATE
               "doc": l2_doc,
               "sig": l2_sig,
               "previous": previous_array }.transform_keys(&:to_s)

        # build actual DID document
        log_str = multi_hash(canonical(l2), LOG_HASH_OPTIONS).first
        if !doc_location.nil?
            log_str += LOCATION_PREFIX + doc_location.to_s
        end
        didDocument = { "doc": did_doc,
                        "key": did_key,
                        "log": log_str }.transform_keys(&:to_s)

        # create DID
        l1_doc = multi_hash(canonical(didDocument), options).first
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
                "sig": sign(l1_doc, privateKey, options).first,
                "previous": [options[:previous_clone].to_s]
            }
            retVal = HTTParty.post(options[:source_location] + "/log/" + options[:source_did],
                headers: { 'Content-Type' => 'application/json' },
                body: {"log": new_log}.to_json )
            prev_hash = [multi_hash(canonical(new_log), LOG_HASH_OPTIONS).first]
        end

        # build creation log entry
        log_revoke_encrypted_array = nil
        l1_sig = nil
        if operation_mode == 3 # UPDATE
            if !options[:cmsm]
                l1_sig = sign(l1_doc, old_privateKey, options).first
            end
            l1 = { "ts": ts,
                   "op": operation_mode, # UPDATE
                   "doc": l1_doc,
                   "sig": l1_sig,
                   "previous": prev_hash }.transform_keys(&:to_s)
            options[:confirm_logs].each do |el|
                # read each log entry to check if it is a revocation delegation
                log_item, msg = retrieve_log_item(el, doc_location, options)
                if log_item["doc"][0..3] == "rev:"
                    cipher, msg = encrypt(r1.to_json, log_item["encryption-key"], {})
                    cipher[:log] = el.to_s
                    if log_revoke_encrypted_array.nil?
                        log_revoke_encrypted_array = [cipher]
                    else
                        log_revoke_encrypted_array << cipher
                    end
                end
            end unless options[:confirm_logs].nil?
        else
            if !options[:cmsm]
                l1_sig = sign(l1_doc, privateKey, options).first
            end
            l1 = { "ts": ts,
                   "op": operation_mode, # CREATE
                   "doc": l1_doc,
                   "sig": l1_sig,
                   "previous": prev_hash }.transform_keys(&:to_s)
        end

        # did, didDocument, revoc_log, l1, l2, r1, privateKey, revocationKey, did_old, log_old, msg = Oydid.generate_base(content, "", "create", options)
        # did_doc = [did, didDocument, did_old]
        # did_log = [revoc_log, l1, l2, r1, log_old]
        # did_key = [privateKey, revocationKey]
        did_doc = {
            :did => did,
            :didDocument => didDocument,
            :did_old => did_old
        }
        did_log = {
            :revoc_log => revoc_log,
            :l1 => l1,
            :l2 => l2,
            :r1 => r1,
            :log_old => log_old
        }
        if !log_revoke_encrypted_array.nil?
            did_log[:r1_encrypted] = log_revoke_encrypted_array
        end

        did_key = {
            :privateKey => privateKey,
            :revocationKey => revocationKey
        }
        return [did_doc, did_key, did_log, ""]
        # return [did, didDocument, revoc_log, l1, l2, r1, privateKey, revocationKey, did_old, log_old, ""]
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

    def self.persist_cmsm(pubkey, payload, options)
        doc_location = options[:doc_location]
        if doc_location.to_s == ""
            doc_location = DEFAULT_LOCATION
        end
        doc_location = doc_location.sub("%3A%2F%2F","://").sub("%3A", ":")

        my_body = {
            pubkey: pubkey,
            payload: payload.to_json
        }
        case doc_location.to_s
        when /^http/
            persist_url = doc_location.to_s + "/cmsm"
            retVal = HTTParty.post(persist_url,
                headers: { 'Content-Type' => 'application/json' },
                body: my_body.to_json )
            if retVal.code != 200
                err_msg = retVal.parsed_response("error").to_s rescue "invalid response from " + doc_location.to_s + "/cmsm"
                return [false, err_msg]
            end
        else
            return [nil, "location not supported for persisting data in cmsm-flow"]
        end
        return [true, ""]

    end

    def self.check_cmsm(pubkey, options)
        doc_location = options[:doc_location]
        if doc_location.to_s == ""
            doc_location = DEFAULT_LOCATION
        end
        doc_location = doc_location.sub("%3A%2F%2F","://").sub("%3A", ":")

        case doc_location.to_s
        when /^http/
            retVal = HTTParty.get(doc_location + "/cmsm/" + pubkey)
            if retVal.code != 200
                msg = retVal.parsed_response["error"].to_s rescue ""
                if msg.to_s == ""
                    msg = "invalid response from " + doc_location.to_s + "/cmsm/" + pubkey.to_s
                end
                return [nil, msg]
            end
            return [retVal.parsed_response.transform_keys(&:to_s), ""]
        else
            return [nil, "location not supported for querying data in cmsm-flow"]
        end
        return [payload, ""]
    end

    def self.write(content, did, mode, options)
        did_doc, did_key, did_log, msg = generate_base(content, did, mode, options)
        if msg != ""
            if msg == "cmsm"
                return [did_doc, 'cmsm']
            end
            return [nil, msg]
        end
        did = did_doc[:did]
        didDocument = did_doc[:didDocument]
        did_old = did_doc[:did_old]
        revoc_log = did_log[:revoc_log]
        l1 = did_log[:l1]
        l2 = did_log[:l2]
        r1 = did_log[:r1]
        r1_encrypted = did_log[:r1_encrypted]
        log_old = did_log[:log_old]
        privateKey = did_key[:privateKey]
        revocationKey = did_key[:revocationKey]
        # did, didDocument, revoc_log, l1, l2, r1, privateKey, revocationKey, did_old, log_old, msg = generate_base(content, did, mode, options)

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
            logs = [revoc_log, l1, l2, r1_encrypted].flatten.compact
        else
            logs = [log_old, revoc_log, l1, l2].flatten.compact
            if !did_old.nil?
                write_private_storage([log_old, revoc_log, l1, l2].flatten.compact.to_json, did10_old + ".log")
            end
        end

        success, msg = publish(did, didDocument, logs, options)

        if success
            didDocumentBackup = Marshal.load(Marshal.dump(didDocument))
            w3c_input = {
                "did" => did.clone,
                "doc" => didDocument.clone
            }
            doc_w3c = w3c(w3c_input, options)
            didDocument = didDocumentBackup
            retVal = {
                "did" => did,
                "doc" => didDocument,
                "doc_w3c" => doc_w3c,
                "log" => logs
            }
            if options[:return_secrets]
                retVal["private_key"] = privateKey
                retVal["revocation_key"] = revocationKey
                retVal["revocation_log"] = r1
            else
                write_private_storage(privateKey, did10 + "_private_key.enc")
                write_private_storage(revocationKey, did10 + "_revocation_key.enc")
                write_private_storage(r1.to_json, did10 + "_revocation.json")
            end

            return [retVal, ""]
        else
            return [nil, msg]
        end
    end

    def self.write_log(did, log, options = {})
        # validate log
        if !log.is_a?(Hash)
            return [nil, "invalid log input"]
        end
        log = log.transform_keys(&:to_s)
        if log["ts"].nil?
            return [nil, "missing timestamp in log"]
        end
        if log["op"].nil?
           return [nil, "missing operation in log"]
        end 
        if log["doc"].nil?
           return [nil, "missing doc entry in log"]
        end 
        if log["sig"].nil?
           return [nil, "missing signature in log"]
        end

        # validate did
        if did.include?(LOCATION_PREFIX)
            tmp = did.split(LOCATION_PREFIX)
            did = tmp[0]
            source_location = tmp[1]
            log_location = tmp[1]
        end
        if did.include?(CGI.escape LOCATION_PREFIX)
            tmp = did.split(CGI.escape LOCATION_PREFIX)
            did = tmp[0] 
            source_location = tmp[1]
            log_location = tmp[1]
        end

        if source_location.to_s == ""
            if options[:doc_location].nil?
                source_location = DEFAULT_LOCATION
            else
                source_location = options[:doc_location]
            end
            if options[:log_location].nil?
                log_location = DEFAULT_LOCATION
            else
                log_location = options[:log_location]
            end
        end
        options[:doc_location] = source_location
        options[:log_location] = log_location
        source_did, msg = read(did, options)
        if source_did.nil?
            return [nil, "cannot resolve DID (on writing logs)"]
        end
        if source_did["error"] != 0
            return [nil, source_did["message"].to_s]
        end
        if source_did["doc_log_id"].nil?
            return [nil, "cannot parse DID log"]
        end

        # write log
        source_location = source_location.gsub("%3A",":")
        source_location = source_location.gsub("%2F%2F","//")
        retVal = HTTParty.post(source_location + "/log/" + did,
            headers: { 'Content-Type' => 'application/json' },
            body: {"log": log}.to_json )
        code = retVal.code rescue 500
        if code != 200
            err_msg = retVal.parsed_response["error"].to_s rescue "invalid response from " + source_location.to_s + "/log"
            return ["", err_msg]
        end
        log_hash = retVal.parsed_response["log"] rescue ""
        if log_hash == ""
            err_msg = "missing log hash from " + source_location.to_s + "/log"
            return ["", err_msg]
        end
        return [log_hash, nil]
    end

    def self.revoke_base(did, options)
        did_orig = did.dup
        doc_location = options[:doc_location]
        if options[:ts].nil?
            ts = Time.now.utc.to_i
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

        msg = ""
        if options[:old_doc_key].nil?
            if options[:old_doc_enc].nil?
                if options[:old_doc_pwd].nil?
                    privateKey_old = read_private_storage(did10_old + "_private_key.enc")
                else
                    privateKey_old, msg = generate_private_key(options[:old_doc_pwd].to_s, options[:key_type]+'-priv', options)
                end
            else
                privateKey_old = options[:old_doc_enc].to_s
            end
        else
            privateKey_old, msg = read_private_key(options[:old_doc_key].to_s, options)
        end
        if privateKey_old.nil?
            return [nil, "invalid or missing old private document key"]
        end
        if options[:old_rev_key].nil?
            if options[:old_rev_enc].nil?
                if options[:old_rev_pwd].nil?
                    revocationKey_old = read_private_storage(did10_old + "_revocation_key.enc")
                else
                    revocationKey_old, msg = generate_private_key(options[:old_rev_pwd].to_s, options[:key_type]+'-priv', options)
                end
            else
                revocationKey_old = options[:old_rev_enc].to_s
            end
        else
            revocationKey_old, msg = read_private_key(options[:old_rev_key].to_s, options)
        end
        if revocationKey_old.nil?
            return [nil, "invalid or missing old private revocation key"]
        end

        if options[:rev_key].nil? && options[:rev_pwd].nil? && options[:rev_enc].nil?
            # revocationKey, msg = read_private_key(did10 + "_revocation_key.enc", options)
            revocationLog = read_private_storage(did10 + "_revocation.json")
        else

            # check if provided old keys are native DID keys or delegates ==================
            msg = ""
            if options[:doc_key].nil?
                if options[:doc_enc].nil?
                    old_privateKey, msg = generate_private_key(options[:old_doc_pwd].to_s, options[:key_type]+'-priv', options)
                else
                    old_privateKey = options[:old_doc_enc].to_s
                end
            else
                old_privateKey, msg = read_private_key(options[:old_doc_key].to_s, options)
            end
            if options[:rev_key].nil?
                if options[:rev_enc].nil?
                    old_revocationKey, msg = generate_private_key(options[:old_rev_pwd].to_s, options[:key_type]+'-priv', options)
                else
                    old_revocationKey = options[:old_rev_enc].to_s
                end
            else
                old_revocationKey, msg = read_private_key(options[:old_rev_key].to_s, options)
            end
            old_publicDocKey = public_key(old_privateKey, {}).first
            old_publicRevKey = public_key(old_revocationKey, {}).first
            old_did_key = old_publicDocKey + ":" + old_publicRevKey

            # compare old keys with existing DID Document & generate revocation record
            if old_did_key.to_s == did_info["doc"]["key"].to_s
                # provided keys are native DID keys ------------------

                # re-build revocation document
                old_did_doc = did_info["doc"]["doc"]
                old_ts = did_info["log"].last["ts"]
                old_subDid = {"doc": old_did_doc, "key": old_did_key}.to_json
                old_subDidHash = multi_hash(canonical(old_subDid), LOG_HASH_OPTIONS).first
                old_signedSubDidHash = sign(old_subDidHash, old_revocationKey, LOG_HASH_OPTIONS).first
                revocationLog = { 
                    "ts": old_ts,
                    "op": 1, # REVOKE
                    "doc": old_subDidHash,
                    "sig": old_signedSubDidHash }.transform_keys(&:to_s).to_json
            else
                # proviced keys are either delegates or invalid ------
                # * check validity of key-doc delegate
                pubKeys, msg = getDelegatedPubKeysFromDID(did, "doc")
                if !pubKeys.include?(old_publicDocKey)
                    return [nil, "invalid or missing private document key"]
                end

                # * check validity of key-rev delegate
                pubKeys, msg = getDelegatedPubKeysFromDID(did, "rev")
                if !pubKeys.include?(old_publicRevKey)
                    return [nil, "invalid or missing private revocation key"]
                end

                # retrieve revocationLog from previous in key-rev delegate
                revoc_log = nil
                log_old.each do |item|
                    if !item["encrypted-revocation-log"].nil?
                        revoc_log = item["encrypted-revocation-log"]
                    end
                end
                if revoc_log.nil?
                    return [nil, "cannot retrieve revocation log"]
                end
                revocationLog, msg = decrypt(revoc_log.to_json, old_revocationKey.to_s)
                if revocationLog.nil?
                    return [nil, "cannot decrypt revocation log entry: " + msg]
                end
            end # compare old keys with existing DID Document
        end

        if revocationLog.nil?
            return [nil, "private revocation key not found"]
        end

        # check if REVOCATION hash matches hash in TERMINATION
        if did_info["log"][did_info["termination_log_id"]]["doc"] != multi_hash(canonical(revocationLog), LOG_HASH_OPTIONS).first
            return [nil, "invalid revocation information"]
        end
        revoc_log = JSON.parse(revocationLog)
        revoc_log["previous"] = [
            multi_hash(canonical(log_old[did_info["doc_log_id"].to_i]), LOG_HASH_OPTIONS).first, 
            multi_hash(canonical(log_old[did_info["termination_log_id"].to_i]), LOG_HASH_OPTIONS).first,
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
            tmp = did.split(LOCATION_PREFIX)
            did = tmp[0]
            source_location = tmp[1]
        end
        if did.include?(CGI.escape LOCATION_PREFIX)
            tmp = did.split(CGI.escape LOCATION_PREFIX)
            did = tmp[0] 
            source_location = tmp[1]
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
        options[:previous_clone] = multi_hash(canonical(source_log), LOG_HASH_OPTIONS).first + LOCATION_PREFIX + source_location
        options[:source_location] = source_location
        options[:source_did] = source_did["did"]
        retVal, msg = write(source_did["doc"]["doc"], nil, "clone", options)
        return [retVal, msg]
    end

    def self.delegate(did, options)
        # check location
        location = options[:doc_location]
        if location.to_s == ""
            location = DEFAULT_LOCATION
        end
        if did.include?(LOCATION_PREFIX)
            tmp = did.split(LOCATION_PREFIX)
            did = tmp[0]
            location = tmp[1]
        end
        if did.include?(CGI.escape LOCATION_PREFIX)
            tmp = did.split(CGI.escape LOCATION_PREFIX)
            did = tmp[0] 
            location = tmp[1]
        end
        options[:doc_location] = location
        options[:log_location] = location

        if options[:ts].nil?
            ts = Time.now.utc.to_i
        else
            ts = options[:ts]
        end

        # build log record
        log = {}
        log["ts"] = ts
        log["op"] = 5 # DELEGATE
        pwd = false
        doc_privateKey, msg = getPrivateKey(options[:doc_enc], options[:doc_pwd], options[:doc_key], "", options)
        rev_privateKey, msg = getPrivateKey(options[:rev_enc], options[:rev_pwd], options[:rev_key], "", options)
        if !doc_privateKey.nil?
            pwd="doc"
            privateKey = doc_privateKey
        end
        if !rev_privateKey.nil?
            pwd="rev"
            privateKey = rev_privateKey
        end
        if !pwd || privateKey.to_s == ""
            return [nil, "missing or invalid delegate key"]
        end
        log["doc"] = pwd + ":" + public_key(privateKey, options).first.to_s
        log["sig"] = sign(privateKey, privateKey, options).first
        log["previous"] = [did] # DID in previous cannot be resolved in the DAG but guarantees unique log hash

        # revocation delegate keys need to specify a public key for encrypting the revocation record
        if pwd == "rev"
            publicEncryptionKey, msg = public_key(privateKey, {}, 'x25519-pub')
            log["encryption-key"] = publicEncryptionKey
        end
        log_hash, msg = write_log(did, log, options)
        if log_hash.nil?
            return [nil, msg]
        else
            return [{"log": log_hash}, ""]
        end
    end

    def self.w3c(did_info, options)
        # check if doc is already W3C DID
        is_already_w3c_did = (did_info.transform_keys(&:to_s)["doc"]["doc"].has_key?("@context") &&
            did_info.transform_keys(&:to_s)["doc"]["doc"].has_key?("id") &&
            did_info.transform_keys(&:to_s)["doc"]["doc"]["id"].split(":").first == "did") rescue false
        if is_already_w3c_did
            return did_info.transform_keys(&:to_s)["doc"]["doc"]
        end
        did = percent_encode(did_info["did"])
        if !did.start_with?("did:oyd:")
            did = "did:oyd:" + did
        end

        didDoc = did_info.dup.transform_keys(&:to_s)["doc"]
        pubDocKey = didDoc["key"].split(":")[0] rescue ""
        pubRevKey = didDoc["key"].split(":")[1] rescue ""
        delegateDocKeys = getDelegatedPubKeysFromDID(did, "doc").first - [pubDocKey] rescue []
        if delegateDocKeys.is_a?(String)
            if delegateDocKeys == pubDocKey
                delegateDocKeys = nil
            else
                delegateDocKeys = [delegateDocKeys]
            end
        end
        delegateRevKeys = getDelegatedPubKeysFromDID(did, "rev").first - [pubRevKey] rescue []
        if delegateRevKeys.is_a?(String)
            if delegateRevKeys == pubRevKey
                delegateRevKeys = nil
            else
                delegateRevKeys = [delegateRevKeys]
            end
        end

        oyd_context = ["https://www.w3.org/ns/did/v1"]
        pubkey = multi_decode(pubDocKey).first
        if pubkey.bytes.length == 34
            code = pubkey.bytes.first
            digest = pubkey[-32..]
        else
            if pubkey.start_with?("\x80\x24".dup.force_encoding('ASCII-8BIT'))
                code = 4608 # Bytes 0x80 0x24 sind das Varint-Encoding des Multicodec-Codes 0x1200 (p256-pub)
                            # 4608 == Oydid.read_varint("\x80$") oder "\x80\x24".force_encoding('ASCII-8BIT')
            else
                code = pubkey.unpack('n').first
            end
            digest = pubkey[-1*(pubkey.bytes.length-2)..]
        end
        case Multicodecs[code].name
        when 'ed25519-pub'
            oyd_context << "https://w3id.org/security/suites/ed25519-2020/v1"
        when 'p256-pub'
            oyd_context << "https://w3id.org/security/suites/jws-2020/v1"
        else
            return {"error": "unsupported key codec (" + Multicodecs[code].name.to_s + ")"}
        end

        wd = {}
        if didDoc["doc"].is_a?(Hash) 
            if didDoc["doc"]["@context"].nil?
                wd["@context"] = oyd_context
            else
                if didDoc["doc"]["@context"].is_a?(Array)
                    wd["@context"] = (oyd_context + didDoc["doc"]["@context"]).uniq
                else
                    oyd_context << didDoc["doc"]["@context"]
                    wd["@context"] = oyd_context.uniq
                end
                didDoc["doc"].delete("@context")
            end
        else
            wd["@context"] = oyd_context
        end
        wd["id"] = percent_encode(did)
        case Multicodecs[code].name
        when 'ed25519-pub'
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
        when 'p256-pub'
            pubDocKey_jwk, msg = public_key_to_jwk(pubDocKey)
            if pubDocKey_jwk.nil?
                return {"error": "document key: " + msg.to_s}
            end
            pubRevKey_jwk, msg = public_key_to_jwk(pubRevKey)
            if pubRevKey_jwk.nil?
                return {"error": "revocation key: " + msg.to_s}
            end
            wd["verificationMethod"] = [{
                "id": did + "#key-doc",
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": pubDocKey_jwk
            },{
                "id": did + "#key-rev",
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": pubRevKey_jwk
            }]
        else
            return {"error": "unsupported key codec (" + Multicodecs[code].name.to_s + ")"}
        end

        if !delegateDocKeys.nil? && delegateDocKeys.count > 0
            i = 0
            wd["capabilityDelegation"] = []
            delegateDocKeys.each do |key|
                i += 1

                delegaton_object = {
                    "id": did + "#key-delegate-doc-" + i.to_s,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": key
                }
                wd["capabilityDelegation"] << delegaton_object
            end
        end
        if !delegateRevKeys.nil? && delegateRevKeys.count > 0
            i = 0
            if wd["capabilityDelegation"].nil?
                wd["capabilityDelegation"] = []
            end
            delegateRevKeys.each do |key|
                i += 1
                delegaton_object = {
                    "id": did + "#key-delegate-rev-" + i.to_s,
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": key
                }
                wd["capabilityDelegation"] << delegaton_object
            end
        end

        equivalentIds = []
        did_info["log"].each do |log|
            if log["op"] == 2 || log["op"] == 3
                eid = percent_encode("did:oyd:" + log["doc"])
                if eid != did
                    equivalentIds << eid
                end
            end
        end unless did_info["log"].nil?
        if equivalentIds.length > 0
            wd["alsoKnownAs"] = equivalentIds
        end

        if didDoc["doc"].is_a?(Hash) && !didDoc["doc"]["service"].nil?
            location = options[:location]
            if location.nil?
                location = get_location(did_info["did"].to_s)
            end
            wd = wd.merge(didDoc["doc"])
            if wd["service"] != []
                if wd["service"].is_a?(Array)
                    wdf = wd["service"].first
                else
                    wdf = wd["service"]
                end
                wdf = { "id": did + "#payload",
                        "type": "Custom",
                        "serviceEndpoint": location }.transform_keys(&:to_s).merge(wdf)
                if wdf["id"][0] == '#'
                    wdf["id"] = did + wdf["id"]
                end
                wd["service"] = [wdf] + wd["service"].drop(1) 
            end
        else
            payload = nil
            if didDoc["doc"].is_a?(Hash)
                if didDoc["doc"] != {}
                    didDoc = didDoc["doc"]
                    # special handling for Verification Methods
                    vms = [ "authentication", 
                            "assertionMethod", 
                            "keyAgreement", 
                            "capabilityInvocation",
                            "capabilityDelegation" ]

                    vms.each do |vm|
                        if didDoc[vm].to_s != ""
                            new_entries = []
                            didDoc[vm].each do |el|
                                if el.is_a?(String)
                                    new_entries << percent_encode(did) + el
                                else
                                    new_el = el.transform_keys(&:to_s)
                                    new_el["id"] = percent_encode(did) + new_el["id"]
                                    new_entries << new_el
                                end
                            end unless didDoc[vm].nil?
                            if new_entries.length > 0
                                wd[vm] = new_entries
                            else
                                wd[vm] = didDoc[vm]
                            end
                            didDoc.delete(vm)
                        end
                    end
                    if didDoc["alsoKnownAs"].to_s != ""
                        if didDoc["alsoKnownAs"].is_a?(Array)
                            dda = didDoc["alsoKnownAs"]
                        else
                            dda = [didDoc["alsoKnownAs"]]
                        end
                        if wd["alsoKnownAs"].nil?
                            wd["alsoKnownAs"] = dda
                        else
                            wd["alsoKnownAs"] += dda
                        end
                        didDoc.delete("alsoKnownAs")
                    end
                    payload = didDoc
                    if payload == {}
                        payload = nil
                    end
                end
            else
                payload = didDoc["doc"]
            end
            if !payload.nil?
                location = options[:location]
                if location.nil?
                    location = get_location(did_info["did"].to_s)
                end
                if payload.is_a?(Array) &&
                        payload.length == 1 &&
                        payload.first.is_a?(Hash) &&
                        !payload.first["id"].nil? &&
                        !payload.first["type"].nil? &&
                        !payload.first["serviceEndpoint"].nil?
                    wd["service"] = payload
                else
                    wd["service"] = [{
                        "id": did + "#payload",
                        "type": "Custom",
                        "serviceEndpoint": location,
                        "payload": payload
                    }]
                end
            end
        end
        return wd
    end


    def self.w3c_legacy(did_info, options)
        did = did_info["did"]
        if !did.start_with?("did:oyd:")
            did = "did:oyd:" + did
        end

        didDoc = did_info.transform_keys(&:to_s)["doc"]
        pubDocKey = didDoc["key"].split(":")[0] rescue ""
        pubRevKey = didDoc["key"].split(":")[1] rescue ""

        wd = {}
        wd["@context"] = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]
        wd["id"] = percent_encode(did)
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

        if didDoc["@context"] == ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]
            didDoc.delete("@context")
        end
        if !didDoc["doc"].nil?
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
                    newDidDoc = didDoc["doc"]
                end
            else
                newDidDoc = didDoc["doc"]
            end
            wd["service"] = newDidDoc
        end
        return wd
    end

    def self.fromW3C(didDocument, options)
        didDocument = didDocument.transform_keys(&:to_s)
        if didDocument["@context"] == ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"]
            didDocument.delete("@context")
        end
        didDocument
    end

end