class ProvidersController < ApplicationController
    include ApplicationHelper
    include ActionController::MimeResponds

    # respond only to JSON requests
    respond_to :json
    respond_to :html, only: []
    respond_to :xml, only: []

    # input
    # {
    #     "args": {
    #         ???
    #     },
    #     "context": {
    #         ???
    #     }
    # }
    def create
        params.permit!
        options = params[:options] || {}
        options[:return_secrets] = true
        secret = params[:secret] || {}
        options = options.to_hash.merge(secret.to_hash).transform_keys(&:to_sym)

        if options[:doc_location] == "local"
            render json: {"error": "location not supported"},
                   status: 500
            return
        end

        if options[:location].to_s != ""
            if !options[:location].start_with?("http")
                options[:location] = "https://" + options[:location]
            end
        end

        if options[:doc_location].nil?
            options[:doc_location] = options[:location]
        end
        if options[:doc_location].to_s != ""
            if !options[:doc_location].start_with?("http")
                options[:doc_location] = "https://" + options[:doc_location]
            end
        end

        if options[:log_location].nil?
            options[:log_location] = options[:location]
        end
        if options[:log_location].to_s != ""
            if !options[:log_location].start_with?("http")
                options[:log_location] = "https://" + options[:log_location]
            end
        end

        if options[:cmsm]
            # Client-Managed-Secret-Mode: the client supplies the public key and,
            # from the second phase on, a signature; private keys never leave it.
            #
            # the key type has to be settled BEFORE the public key is encoded: the
            # multicodec prefix differs per curve (ed25519-pub 0xed01 vs p256-pub
            # 0x1200), so a hard-coded prefix silently mis-encodes the other curve
            if options[:key_type].nil?
                options[:key_type] = 'p256'
            end
            if options[:key_type] == 'Secp256r1'
                options[:key_type] = 'p256'
            end

            # A session handle continues an already started flow; without one the
            # public key(s) start a new one. This driver holds no state itself -
            # the gem persists the session in the repository at
            # options[:doc_location] (POST /cmsm), so every phase of a flow has
            # to name the same location or phase 2 looks in the wrong place.
            if options[:cmsm_session].nil?
                options[:cmsm_session] = options[:session]
            end

            doc = params.except(:options, :secret, :provider, :controller, :action)
            doc = JSON.parse(doc.to_json).transform_keys(&:to_sym)
            if !doc[:key_hex].nil?
                pubkey, msg = Oydid.public_key_from_hex(doc[:key_hex], options)
                if pubkey.nil?
                    render json: {"error": "invalid public key in CMSM: " + msg.to_s},
                           status: 400
                    return
                end
                doc[:key] = pubkey
                doc.delete(:key_hex)
            end

            # a second public key makes the revocation key client-managed too;
            # without it the revocation key is generated for the client
            if !doc[:rev_key_hex].nil?
                if doc[:key].nil?
                    render json: {"error": "rev_key_hex requires key_hex in CMSM"},
                           status: 400
                    return
                end
                revpub, msg = Oydid.public_key_from_hex(doc[:rev_key_hex], options)
                if revpub.nil?
                    render json: {"error": "invalid revocation key in CMSM: " + msg.to_s},
                           status: 400
                    return
                end
                doc[:key] = doc[:key].to_s + ":" + revpub
                doc.delete(:rev_key_hex)
            end

            # The signature stays in options - the gem reads options[:sig] when it
            # resumes a flow. Moving it into doc[:opt], as this driver did, is the
            # shape of the protocol before sessions existed and drops it entirely.

            # from the second phase on the client sends nothing but session and
            # signature, so a missing key is only an error while starting a flow
            if options[:cmsm_session].to_s == "" && doc[:key].nil?
                render json: {"error": "missing public key in CMSM"},
                       status: 400
                return
            end
        else
            # options = {:return_secrets => true}
            doc = {}
            did_obj = JSON.parse(doc.to_json) rescue nil
            if !did_obj.nil? && did_obj.is_a?(Hash)
                if did_obj["@context"] == "https://www.w3.org/ns/did/v1"
                    doc = Oydid.fromW3C(did_obj, options)
                end
            end

            options[:authentication] = true
            if options[:type] == "ES256"
                options[:key_type] = 'p256'
                options[:keyAgreement] = true
            else
                options[:key_type] = 'ed25519'
                options[:x25519_keyAgreement] = true
            end
        end
        status, msg = Oydid.create(doc, options)

        # did_obj = {"keyAgreement":[
        #     {
        #         "id": Oydid.percent_encode(status["did"]) + "#key-doc-x25519", 
        #         "type": "X25519KeyAgreementKey2019", 
        #         "controller": Oydid.percent_encode(status["did"]), 
        #         "publicKeyMultibase": Oydid.public_key(status["private_key"], {}, 'x25519-pub').first
        #     }
        # ]}
        # # did_obj = Oydid.fromW3C(doc_w3c, {})
        # options[:doc_enc] = status["private_key"]
        # options[:old_doc_enc] = status["private_key"]
        # options[:rev_enc] = status["revocation_key"]
        # options[:old_rev_enc] = status["revocation_key"]
        # status, msg = Oydid.update(did_obj, status["did"], options)

        if status.nil?
            render json: {"error": msg},
                   status: client_error?(msg) ? 400 : 500
        elsif msg == "cmsm"
            # intermediate CMSM phase: the gem has persisted the state under the
            # returned session handle; the response says which value the client
            # has to sign and with which key
            render json: status,
                   status: 201
            return
        else
            keys = []
            if options[:type] == "ES256" || options[:key_type] == "p256"
                if !status["private_key"].nil?
                    keyJwk = Oydid.private_key_to_jwk(status["private_key"]).first
                    keys << {
                        "kid": Oydid.percent_encode(status["did"]) +  '#key-doc',
                        "kms": "local",
                        "type": "ES256",
                        "jwk": keyJwk
                    }
                end
            else
                # document key
                code, length, pubKey = Oydid.multi_decode(status["doc"]["key"].split(":")[0]).first.unpack('CCa*')
                pubKeyHex = pubKey.bytes.pack('C*').unpack1('H*')
                code, length, privKey = Oydid.multi_decode(status["private_key"]).first.unpack('SCa*')
                privKeyHex = privKey.bytes.pack('C*').unpack1('H*')
                keys << {
                    "kid": Oydid.percent_encode(status["did"]) +  '#key-doc',
                    "kms": "local",
                    "type": "Ed25519", 
                    "publicKeyHex": pubKeyHex,
                    "privateKeyHex": privKeyHex + pubKeyHex
                }

                # revocation key
                code, length, pubKey = Oydid.multi_decode(status["doc"]["key"].split(":")[1]).first.unpack('CCa*')
                pubKeyHex = pubKey.bytes.pack('C*').unpack1('H*')
                code, length, privKey = Oydid.multi_decode(status["revocation_key"]).first.unpack('SCa*')
                privKeyHex = privKey.bytes.pack('C*').unpack1('H*')
                keys << {
                    "kid": Oydid.percent_encode(status["did"]) +  '#key-rev',
                    "kms": "local",
                    "type": "Ed25519", 
                    "publicKeyHex": pubKeyHex,
                    "privateKeyHex": privKeyHex + pubKeyHex
                }

                # x25519 key agreement
                code, length, pubKey = Oydid.multi_decode(status["doc"]["doc"]["keyAgreement"].first[:publicKeyMultibase]).first.unpack('CCa*')
                pubKeyHex = pubKey.bytes.pack('C*').unpack1('H*')
                code, length, privKey = Oydid.multi_decode(status["private_key"]).first.unpack('SCa*')
                privKeyHex = privKey.bytes.pack('C*').unpack1('H*')
                keys << {
                    "kid": Oydid.percent_encode(status["did"]) +  '#key-doc-x25519',
                    "kms": "local",
                    "type": "X25519", 
                    "publicKeyHex": pubKeyHex,
                    "privateKeyHex": privKeyHex + pubKeyHex
                }
            end

            retVal = {
                "did": Oydid.percent_encode(status["did"]),
                "controllerKeyId": Oydid.percent_encode(status["did"]) +  '#key-doc',
                "keys": keys,
                "services": []
            }

            render json: retVal.to_json,
                   status: 200
        end
    end

    # input
    # {
    #     "args": {
    #         "did":"did:oyd:...",
    #         ???
    #     },
    #     "context": {
    #         ???
    #     }
    # }
    def update
        old_did = (params[:args][:did] rescue nil)

        params.permit!
        options = params[:options] || {}
        options[:return_secrets] = true
        secret = params[:secret] || {}
        options = options.to_hash.merge(secret.to_hash).transform_keys(&:to_sym)

        if options[:cmsm]
            cmsm_update(old_did, params[:didDocument], options)
            return
        end

        did_obj = {} # JSON.parse(didDocument.to_json) rescue nil
        if !did_obj.nil? && did_obj.is_a?(Hash)
            if did_obj["@context"] == "https://www.w3.org/ns/did/v1"
                did_obj = Oydid.fromW3C(did_obj, options)
            end
        end

        preprocessed = false
        msg = ""
        if !did_obj.nil? && did_obj.is_a?(Hash)
            if !options[:log_revoke].nil? && !options[:log_update].nil? && !options[:log_terminate].nil?
                preprocessed = true

                # perform sanity checks on input data =========

                # check valid signature in update create record
                doc_pubkey = did_obj["key"].split(":")[0].to_s
                old_doc_location = Oydid.get_location(old_did)
                old_didDocument = Oydid.retrieve_document_raw(old_did, "", old_doc_location, {})
                old_doc_pubkey = old_didDocument.first["doc"]["key"].split(":")[0].to_s
                success, msg = Oydid.verify(options[:log_update]["doc"], options[:log_update]["sig"], old_doc_pubkey)
                if !success
                    render json: {"error": "invalid input data (update log has invalid signature)"},
                           status: 400
                    return
                end

                # update DID
                did = "did:oyd:" + Oydid.multi_hash(Oydid.canonical(did_obj), options).first
                logs = [options[:log_revoke], options[:log_update], options[:log_terminate]]
                success, msg = Oydid.publish(did, did_obj, logs, options)
                if success
                    w3c_input = {
                        "did" => did,
                        "doc" => did_obj
                    }
                    status = {
                        "did" => did,
                        "doc" => did_obj,
                        "doc_w3c" => Oydid.w3c(w3c_input, options),
                        "log" => logs,
                        "private_key" => "",
                        "revocation_key" => "",
                        "revocation_log" => []
                    }
                else
                    status = nil
                end
            end
        end

        if !preprocessed
            status, msg = Oydid.update(did_obj, old_did, options)
        end
        if status.nil?
            render json: {"error": msg},
                   status: 500
        else
            keys = []

            # document key
            keys << {
                "kid": Oydid.percent_encode(status["did"]) +  '#key-doc',
                "kms": "local",
                "type": "Ed25519", 
                "publicKeyHex": Oydid.multi_decode(status["doc"]["key"].split(":")[0]).first.unpack('H*').first,
                "privateKeyHex": Oydid.multi_decode(status["private_key"]).first.unpack('H*').first
            }

            # revocation key
            keys << {
                "kid": Oydid.percent_encode(status["did"]) +  '#key-rev',
                "kms": "local",
                "type": "Ed25519", 
                "publicKeyHex": Oydid.multi_decode(status["doc"]["key"].split(":")[1]).first.unpack('H*').first,
                "privateKeyHex": Oydid.multi_decode(status["revocation_key"]).first.unpack('H*').first
            }

            retVal = {
                "did": Oydid.percent_encode(status["did"]),
                "provider": "https://oydid.ownyourdata.eu",
                "controllerKeyId": Oydid.percent_encode(status["did"]) +  '#key-doc',
                "keys": keys,
                "services": []
            }
            render json: retVal.to_json,
                   status: 200
        end
    end

    # input
    # {
    #     "identifier": {
    #         "did":"did:oyd:...",
    #         ???
    #     },
    #     "context": {
    #         ???
    #     }
    # }
    def deactivate
        did = params[:identifier][:did]
        params.permit!
        options = params[:options] || {}
        options[:return_secrets] = true
        secret = params[:secret] || {}
        options = options.to_hash.merge(secret.to_hash).transform_keys(&:to_sym)
        if options[:old_doc_pwd].nil? && !options[:doc_pwd].nil?
            options[:old_doc_pwd] = options[:doc_pwd]
        end
        if options[:old_rev_pwd].nil? && !options[:rev_pwd].nil?
            options[:old_rev_pwd] = options[:rev_pwd]
        end
        if options[:doc_location] == "local"
            render json: {"error": "location not supported"},
                   status: 500
            return
        end

        if options[:cmsm] && options[:key_type].to_s == 'Secp256r1'
            options[:key_type] = 'p256'
        end

        # Both modes go through here: with the controller keys from `secret`, or
        # - when the client holds them and cannot sign here - with the
        # revocation record it kept, which the gem verifies against the current
        # document before accepting it. That is also all a CMSM revoke needs:
        # one call, no signature, options[:log_revoke].
        #
        # This used to set a `preprocessed` flag on options[:log_revoke] and then
        # run an empty block, leaving `status` nil - every client-held revocation
        # answered 500 without ever revoking anything.
        status, msg = Oydid.revoke(did, options)

        if status.nil?
            render json: {"error": msg},
                   status: client_error?(msg) ? 400 : 500
        else
            retVal = {
                "did": Oydid.percent_encode(did),
                "success": true
            }
            render json: retVal.to_json,
                   status: 200
        end
    end

    private

    # Client-Managed-Secret-Mode update. Phase 1 carries the new DID document,
    # the new public key(s) and the revocation record of the current document;
    # every later phase carries only the session and one signature.
    #
    # Unlike the repository this driver has no session store of its own - the
    # gem keeps the flow in a repository over HTTP, so which DID is being
    # updated has to be read back from there.
    def cmsm_update(old_did, didDocument, options)
        if options[:key_type].nil?
            options[:key_type] = 'p256'
        end
        if options[:key_type] == 'Secp256r1'
            options[:key_type] = 'p256'
        end
        if options[:cmsm_session].nil?
            options[:cmsm_session] = options[:session]
        end

        if options[:cmsm_session].to_s == ""
            did_obj = JSON.parse((didDocument || {}).to_json) rescue {}
            did_obj = {} if !did_obj.is_a?(Hash)
            if did_obj["@context"] == "https://www.w3.org/ns/did/v1"
                did_obj = Oydid.fromW3C(did_obj, options)
            end

            key, err = cmsm_public_keys(options)
            if key.nil?
                render json: {"error": err}, status: 400
                return
            end
            did_obj["key"] = key

            if options[:log_revoke_old].nil?
                render json: {"error": "CMSM update requires the revocation record of the current document (log_revoke_old)"},
                       status: 400
                return
            end
        else
            did_obj = {}
            # from the second phase on the client sends nothing but session and
            # signature - which DID is being updated comes from the flow
            if old_did.to_s == ""
                stored, msg = Oydid.check_cmsm(options[:cmsm_session], options)
                if stored.nil?
                    render json: {"error": msg},
                           status: client_error?(msg) ? 400 : 500
                    return
                end
                old_did = stored["did_old"].to_s
                # dag_update stores the bare log hash, without the method prefix
                if old_did != "" && !old_did.start_with?("did:oyd:")
                    old_did = "did:oyd:" + old_did
                end
            end
        end

        if old_did.to_s == ""
            render json: {"error": "missing DID"},
                   status: 400
            return
        end

        status, msg = Oydid.update(did_obj, old_did, options)
        if status.nil?
            render json: {"error": msg},
                   status: client_error?(msg) ? 400 : 500
            return
        elsif msg == "cmsm"
            render json: status,
                   status: 201
            return
        end

        render json: {
            "did": Oydid.percent_encode(status["did"]),
            "did_old": Oydid.percent_encode(old_did),
            "provider": request.base_url,
            "controllerKeyId": Oydid.percent_encode(status["did"]) + '#key-doc',
            "keys": [],
            "services": [],
            # replaces the record the client kept for the previous document
            "log_revoke": status["revocation_log"]
        }.to_json, status: 200
    end

    # turn the hex-encoded public keys of a CMSM request into the "key" field of
    # a DID document ("<doc>" or "<doc>:<rev>")
    def cmsm_public_keys(options)
        key_hex = params[:key_hex]
        rev_hex = params[:rev_key_hex]
        if key_hex.nil?
            return [nil, "missing public key in CMSM"]
        end
        pubkey, msg = Oydid.public_key_from_hex(key_hex, options)
        if pubkey.nil?
            return [nil, "invalid public key in CMSM: " + msg.to_s]
        end
        return [pubkey, nil] if rev_hex.nil?

        revpub, msg = Oydid.public_key_from_hex(rev_hex, options)
        if revpub.nil?
            return [nil, "invalid revocation key in CMSM: " + msg.to_s]
        end
        [pubkey + ":" + revpub, nil]
    end


    # Messages the gem raises about client input. Without this every one of them
    # would leave here as a 500, and a client could not tell "you sent something
    # wrong" from "the server broke".
    CLIENT_ERRORS = [
        "unknown or expired CMSM session",
        "missing signature in CMSM flow (sig)",
        "invalid persisted data in CMSM flow"
    ].freeze

    def client_error?(msg)
        msg = msg.to_s
        return true if CLIENT_ERRORS.include?(msg)
        # anything the gem reports about a CMSM input or about a revocation
        # record supplied by the client is a bad request, not a server fault.
        # "log_revoke" covers "log_revoke_old" as well.
        msg.start_with?("CMSM ") || msg.include?("log_revoke")
    end
end
