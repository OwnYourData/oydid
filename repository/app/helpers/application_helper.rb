module ApplicationHelper
    # Persist a DID document and its log entries in the local database.
    #
    # didHash        : DID identifier without the "did:oyd:" prefix and without
    #                  any location suffix
    # didDocument    : the DID document (Hash or JSON string)
    # logs           : array of log entries; entries with an "op" key are stored
    #                  as new log records, entries with a "log" key carry an
    #                  encrypted-revocation-log update for an existing record
    #
    # Returns [true, ""] on success or [false, message] on error.
    def local_store_did(didHash, didDocument, logs)
        didHash = didHash.to_s.delete_prefix("did:oyd:")
        didHash = didHash.split(LOCATION_PREFIX).first rescue didHash

        didDocumentJson = didDocument.is_a?(String) ? didDocument : didDocument.to_json
        didDoc = JSON.parse(didDocumentJson) rescue nil
        if didDoc.nil?
            return [false, "cannot parse did-document"]
        end
        didPubKey = didDoc["key"].split(":")[0] rescue nil
        if didPubKey.nil?
            return [false, "missing public document key in did-document"]
        end

        if Did.find_by_did(didHash).nil?
            # Guardrail: at any time a public key controls at most one active
            # DID. Only CREATE is refused - a non-rotating UPDATE legitimately
            # carries the key of the version it replaces, and that is the most
            # common form of update.
            if document_operation(logs, didHash) == 2 && Did.key_in_active_use?(didPubKey)
                return [false, KEY_IN_USE_ERROR]
            end
            Did.new(did: didHash, doc: didDocumentJson, public_key: didPubKey).save
        end

        Array(logs).compact.each do |raw_item|
            item = JSON.parse(raw_item.to_json) rescue nil
            next if item.nil? || !item.is_a?(Hash)

            if item.key?("op")
                entry_hash, sub_hash = Log.hashes_for(item, LOG_HASH_OPTIONS)
                if !Log.stored?(entry_hash, sub_hash)
                    Log.new(did: didHash, item: item.to_json, oyd_hash: entry_hash,
                            sub_hash: sub_hash, ts: Time.now.utc.to_i).save
                end
            else
                # encrypted-revocation-log update for an existing log record
                @log = Log.find_by_any_hash(item["log"]) rescue nil
                if !@log.nil?
                    payload = JSON.parse(@log.item) rescue nil
                    if !payload.nil?
                        payload["encrypted-revocation-log"] = item.slice("value", "nonce")
                        @log.update(item: payload.to_json)
                    end
                end
            end
        end

        return [true, ""]
    end

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
        #
        # did_requested keeps the identifier the caller asked for: dag_update
        # below walks the log and replaces "did" with every version it passes,
        # so without this the requested identifier is gone by the time the
        # document is rendered. Same contract as Oydid.read.
        currentDID = {
            "did": did,
            "did_requested": did,
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
        revoked = false
        rotation_performed = false
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
                    # signature for CREATE is optional (due to CMSM)
                    if !el["sig"].nil?
                        if !Oydid.match_log_did?(el, doc)
                            currentDID["error"] = 1
                            currentDID["message"] = "Signatures in log don't match"
                            return currentDID
                        end
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
                current_public_doc_key = currentDID["doc"]["key"].split(":")[0] rescue ""
            when 0 # TERMINATE
                currentDID["termination_log_id"] = i

                doc_did = currentDID["did"]
                doc_location = Oydid.get_location(doc_did)
                did_hash = doc_did.delete_prefix("did:oyd:")
                did_hash = did_hash.split("@").first
                did10 = did_hash[0,10]
                did, doc = local_retrieve_document(did_hash)

                if !Oydid.match_log_did?(el, doc)
                    currentDID["error"] = 1
                    currentDID["message"] = "Signatures in log don't match"
                    return currentDID
                end

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
                    if log_el["op"].to_i == 1 # REVOKE
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
                                        if pubKeys.include?(next_doc["key"].split(":")[0])
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
                    # the revocation record is published and no UPDATE record
                    # builds on it: this DID is revoked. The verdict is only
                    # acted upon after the log has been walked completely, so
                    # that DID Rotation (handled in the REVOKE entry below) can
                    # still take precedence.
                    revoked = !update_term_found
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
                                when "did:ebsi", "did:cheqd"
                                    public_resolver = ENV["PUBLIC_RESOLVER"] || DEFAULT_PUBLIC_RESOLVER
                                    rotate_DID_Document = HTTParty.get(public_resolver + rotate_DID)
                                    rotate_ddoc = JSON.parse(rotate_DID_Document.parsed_response)

                                    # checks
                                    # 1) is original DID revoked -> fulfilled, otherwise we would not be in this branch
                                    # 2) das new DID reference back original DID

                                    currentDID["did"] = rotate_DID
                                    currentDID["doc"]["doc"] = rotate_ddoc["didDocument"]
                                    rotation_performed = true
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

        # fail closed: a revoked DID has no resolvable DID Document unless the
        # controller rotated it to another DID via alsoKnownAs
        if revoked && !rotation_performed
            currentDID["error"] = REVOKED_ERROR
            currentDID["message"] = "revoked"
        end
        return currentDID
    end

    # HTTP status for an internal resolution error code as produced by
    # resolve_did / Oydid.read. Internal codes (1, 2, ...) are not HTTP status
    # codes and must never be handed to `render status:` directly.
    def http_status_for(error_code)
        case error_code.to_i
        when 0                then 200
        when 404              then 404
        when REVOKED_ERROR    then revoked_http_status
        else                       500
        end
    end

    # 410 Gone by default; set REVOKED_HTTP_STATUS=404 for clients or caches
    # that handle 410 poorly
    def revoked_http_status
        ENV["REVOKED_HTTP_STATUS"].to_s == "404" ? 404 : 410
    end

    # Render a failed DID resolution. A revoked DID answers 410 Gone with
    # {"error":"revoked"} and is explicitly not cacheable.
    # A revoked DID resolves *successfully* - the answer is "deactivated", not
    # "not found". DID Core 7.1.3: "If a DID has been deactivated, DID document
    # metadata MUST include this property with the boolean value true."
    #
    # Only the resolution result can carry that statement, so this shape answers
    # 200 with didDocument null and deliberately *no* didResolutionMetadata
    # error: error stays reserved for identifiers that never existed. A consumer
    # behind a universal-resolver driver never sees the HTTP status, and for a
    # product passport "never existed" and "revoked" have to stay
    # distinguishable. The bare document paths keep answering 410 - that is the
    # right HTTP statement for a request that asks for a document.
    #
    # didDocumentMetadata carries nothing but the verdict: for a DID resolved at
    # another repository there is no document and no log to describe, and this
    # way both branches answer alike.
    def render_deactivated(did, didHash, duration)
        did_string = did.to_s
        did_string = "did:oyd:" + didHash.to_s if !did_string.start_with?("did:oyd:")
        response.headers["Cache-Control"] = "no-store"
        render json: {
                   "didDocument": nil,
                   "didResolutionMetadata": {
                       "contentType": "application/did+ld+json",
                       "pattern": "^(did:oyd:.+)$",
                       "driverUrl": request.base_url.to_s + "/1.0/resolve/$1",
                       "duration": duration,
                       "did": {
                           "didString": Oydid.percent_encode(did_string),
                           "methodSpecificId": didHash,
                           "method": "oyd"
                       }
                   },
                   "didDocumentMetadata": { "deactivated": true }
               },
               content_type: 'application/ld+json',
               status: 200
    end

    # A DID that could not be retrieved. Three outcomes have to stay apart:
    # a revocation reported by the hosting repository, a failure of that
    # repository (5xx, marked by the gem via Oydid.upstream_error?), and an
    # identifier that is genuinely not there. Reporting the middle case as
    # "not found" would claim the DID never existed.
    def render_unresolvable(read_msg)
        if read_msg.to_s == "revoked"
            render_resolution_error({"error" => REVOKED_ERROR, "message" => "revoked"})
        elsif Oydid.upstream_error?(read_msg)
            render json: {"error": read_msg.to_s},
                   status: 502
        else
            render json: {"error": "not found"},
                   status: 404
        end
    end

    def render_resolution_error(result)
        status = http_status_for(result["error"])
        if result["error"].to_i == REVOKED_ERROR
            response.headers["Cache-Control"] = "no-store"
            render json: {"error": "revoked"},
                   status: status
        else
            render json: {"error": result["message"].to_s},
                   status: status
        end
    end

    # Resolve a DID through the local path when it is stored in this repository
    # and remotely through the gem otherwise. Both branches evaluate the full
    # did:oyd resolution including the revocation record.
    # Returns [result, message]; result is nil when the DID cannot be retrieved,
    # in which case the message carries the reason ("revoked" for a remote 410).
    def resolve_did_any(did, options)
        if local_retrieve_document(remove_location(did)).last.nil?
            Oydid.read(did, options) rescue [nil, ""]
        else
            [resolve_did(did, options), ""]
        end
    end

    # Profile a client names in its Accept header to ask for a full DID
    # Resolution Result instead of the bare DID Document.
    DID_RESOLUTION_PROFILE = "https://w3id.org/did-resolution"

    # DID Resolution content negotiation. Without this profile in Accept the
    # caller gets the bare DID Document, which is what every consumer of
    # /1.0/identifiers/ reads today - the default has to stay that way.
    # Quotes around the profile value are optional in the wild, so they are
    # stripped before matching.
    def wants_resolution_result?
        accept = request.headers["Accept"].to_s.delete('"').delete("'")
        accept.include?("profile=" + DID_RESOLUTION_PROFILE)
    end

    # Full DID Resolution Result: didDocument plus didResolutionMetadata and
    # didDocumentMetadata. Built here rather than in the actions because two
    # endpoints serve it now - /1.0/resolve/ always, /1.0/identifiers/ when the
    # client negotiates for it.
    # Returns [payload, error_message]; payload is nil when the keys of the
    # resolved document cannot be represented.
    def did_resolution_result(did, didHash, result, options, duration)
        keys, key_error = resolution_keys(result)
        return [nil, key_error] if keys.nil?

        # The identifier the document carries as `id` - the requested one, which
        # after an update is an earlier version than the document being served.
        # didString describes the input of the resolution, so it is this one too;
        # it used to be the resolved identifier while methodSpecificId right next
        # to it came from the request, which made the two contradict each other.
        did_identifier = Oydid.document_id(result)

        # canonicalId names the version the log resolves to, equivalentId every
        # other version. Together they say in the DID Core vocabulary what
        # alsoKnownAs in the document can only hint at. equivalentId is omitted
        # while there is only one version, rather than sent as an empty array.
        canonical_id, equivalent_ids = Oydid.version_ids(result)
        # No "did" key here: it duplicated didDocument.id, and of all the
        # method-specific keys in this structure it is the one most likely to
        # collide with a future standard name. Consumers read didDocument.id -
        # DID Core requires it to be the DID that was resolved.
        didDocumentMetadata = {
            "keys": keys,
            "registry": Oydid.get_location(result["did"].to_s),
            "log_hash": result["doc"]["log"].to_s,
            "log": result["log"],
            "document_log_id": result["doc_log_id"].to_i,
            "termination_log_id": result["termination_log_id"].to_i,
            "canonicalId": canonical_id
        }
        didDocumentMetadata[:equivalentId] = equivalent_ids if equivalent_ids.any?

        # created / updated / versionId (DID Core 7.1.3). The log carries the
        # timestamps already; without `updated` a consumer cannot tell how old the
        # version in its hands is. Built in the gem so that this endpoint, the
        # uniresolver plugin and any later caller agree - the same reason
        # version_ids lives there.
        Oydid.version_metadata(result).each do |key, value|
            didDocumentMetadata[key.to_sym] = value
        end

        payload = {
            "didDocument": Oydid.w3c(Marshal.load(Marshal.dump(result)), options),
            "didResolutionMetadata": {
                "contentType": "application/did+ld+json",
                "pattern": "^(did:oyd:.+)$",
                "driverUrl": request.base_url.to_s + "/1.0/resolve/$1",
                "duration": duration,
                "did": {
                    "didString": did_identifier,
                    "methodSpecificId": didHash,
                    "method": "oyd"
                }
            },
            "didDocumentMetadata": didDocumentMetadata
        }
        [payload, ""]
    end

    # Verification keys in the didDocumentMetadata format used by the universal
    # resolver. Returns [keys, error_message].
    def resolution_keys(result)
        pubDocKey = result["doc"]["key"].split(":")[0]
        pubkey = Oydid.multi_decode(pubDocKey).first
        if pubkey.bytes.length == 34
            code = pubkey.bytes.first
        elsif pubkey.start_with?("\x80\x24".dup.force_encoding('ASCII-8BIT'))
            # 0x80 0x24 is the varint encoding of multicodec 0x1200 (p256-pub)
            code = 4608
        else
            code = pubkey.unpack('n').first
        end

        # The kid values have to name the same DID the document uses for its
        # verificationMethod fragments, otherwise metadata and document point at
        # two different identifiers for one key.
        did_id = Oydid.document_id(result)
        doc_key = result["doc"]["key"].split(":")[0]
        rev_key = result["doc"]["key"].split(":")[1]

        case Multicodecs[code].name
        when 'ed25519-pub'
            keys = [
                {"kid" => Oydid.percent_encode(did_id) + '#key-doc', "kms" => "local", "type" => "Ed25519",
                 "publicKeyHex" => Oydid.multi_decode(doc_key).first.unpack('H*').first},
                {"kid" => Oydid.percent_encode(did_id) + '#key-rev', "kms" => "local", "type" => "Ed25519",
                 "publicKeyHex" => Oydid.multi_decode(rev_key).first.unpack('H*').first}
            ]
        when 'p256-pub'
            doc_jwk, msg = Oydid.public_key_to_jwk(doc_key)
            return [nil, "document key: " + msg.to_s] if doc_jwk.nil?
            rev_jwk, msg = Oydid.public_key_to_jwk(rev_key)
            return [nil, "revocation key: " + msg.to_s] if rev_jwk.nil?
            keys = [
                {"kid" => Oydid.percent_encode(did_id) + '#key-doc', "kms" => "local",
                 "type" => "JsonWebKey2020", "publicKeyJwk" => doc_jwk},
                {"kid" => Oydid.percent_encode(did_id) + '#key-rev', "kms" => "local",
                 "type" => "JsonWebKey2020", "publicKeyJwk" => rev_jwk}
            ]
        else
            return [nil, "unsupported key codec (" + Multicodecs[code].name.to_s + ")"]
        end
        [keys, nil]
    end

    # Which operation created this version? The document entry of a DID is the
    # log entry whose "doc" names the DID itself; op 2 is CREATE, op 3 UPDATE.
    # Returns nil when the entry is not among the submitted logs.
    def document_operation(logs, didHash)
        Array(logs).compact.each do |raw_item|
            item = JSON.parse(raw_item.to_json) rescue nil
            next if item.nil? || !item.is_a?(Hash)
            next unless [2, 3].include?(item["op"].to_i)
            return item["op"].to_i if Did.strip_location(item["doc"]) == didHash
        end
        nil
    end

    def local_retrieve_document(doc_identifier)
        did = nil
        doc = nil
        @did = Did.find_by_did(doc_identifier)
        if @did.nil?
            @did = Did.find_by_public_key_active(doc_identifier)
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
                @log = Log.find_by_any_hash(remove_location(log["doc"])) rescue nil
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
                    @log = Log.find_by_any_hash(entry) rescue nil
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
