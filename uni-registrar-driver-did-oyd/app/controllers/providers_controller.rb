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
            doc = params.except(:options).except(:secret).except(:provider).except(:controller).except(:action)
            doc = JSON.parse(doc.to_json).transform_keys(&:to_sym)
            if !options[:sig].nil?
                doc[:opt] = {:sig => options[:sig]}
                options.delete(:sig)
            end
            if doc[:key].nil?
                render json: {"error": "missing public key in CMSM"},
                       status: 400
                return
            end
            if options[:key_type].nil?
                options[:key_type] = 'p256'
            end
            if options[:key_type] == 'Secp256r1'
                options[:key_type] = 'p256'
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
                   status: 500
        elsif msg == "cmsm"
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
                code, length, pubKey = Oydid.multi_decode(status["doc"]["key"].split(":").first).first.unpack('CCa*')
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
                code, length, pubKey = Oydid.multi_decode(status["doc"]["key"].split(":").last).first.unpack('CCa*')
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
        old_did = params[:args][:did]
        # old_didDocument = Oydid.read(old_did, {}).first["doc"]

        params.permit!
        options = params[:options] || {}
        options[:return_secrets] = true
        secret = params[:secret] || {}
        options = options.to_hash.merge(secret.to_hash).transform_keys(&:to_sym)

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
                doc_pubkey = did_obj["key"].split(":").first.to_s
                old_doc_location = Oydid.get_location(old_did)
                old_didDocument = Oydid.retrieve_document_raw(old_did, "", old_doc_location, {})
                old_doc_pubkey = old_didDocument.first["doc"]["key"].split(":").first.to_s
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
                "publicKeyHex": Oydid.multi_decode(status["doc"]["key"].split(":").first).first.unpack('H*').first,
                "privateKeyHex": Oydid.multi_decode(status["private_key"]).first.unpack('H*').first
            }

            # revocation key
            keys << {
                "kid": Oydid.percent_encode(status["did"]) +  '#key-rev',
                "kms": "local",
                "type": "Ed25519", 
                "publicKeyHex": Oydid.multi_decode(status["doc"]["key"].split(":").last).first.unpack('H*').first,
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

        preprocessed = false
        msg = ""
        if !options[:log_revoke].nil?
            preprocessed = true

            # perform sanity checks on input data =========

        end
        if !preprocessed
            status, msg = Oydid.revoke(did, options)
        end

        if status.nil?
            render json: {"error": msg},
                   status: 500
        else
            retVal = {
                "did": Oydid.percent_encode(did),
                "success": true
            }
            render json: retVal.to_json,
                   status: 200
        end
    end
end