class DidsController < ApplicationController
    include ApplicationHelper
    include ActionController::MimeResponds

    # respond only to JSON requests
    respond_to :json
    respond_to :html, only: []
    respond_to :xml, only: []

    def show
        options = {}
        if ENV["DID_LOCATION"].to_s != ""
            options[:location] = ENV["DID_LOCATION"].to_s
            if options[:doc_location].nil?
                options[:doc_location] = options[:location]
            end
            if options[:log_location].nil?
                options[:log_location] = options[:location]
            end
        end

        did = params[:did]
        # didHash = did.split(LOCATION_PREFIX).first.split(CGI.escape LOCATION_PREFIX).first rescue did
        # didHash = didHash.delete_prefix("did:oyd:")
        # options[:digest] = Oydid.get_digest(didHash).first
        # options[:encode] = Oydid.get_encoding(didHash).first
        
        result = resolve_did(did, options)
        if result["error"] != 0
            puts "Error: " + result["message"].to_s
            render json: {"error": result["message"].to_s}.to_json,
                   status: 500
        else
            render json: result["doc"],
                   status: 200
        end
    end

    def raw
        options = {}
        if ENV["DID_LOCATION"].to_s != ""
            options[:location] = ENV["DID_LOCATION"].to_s
            if options[:doc_location].nil?
                options[:doc_location] = options[:location]
            end
            if options[:log_location].nil?
                options[:log_location] = options[:location]
            end
        end
        identifier = remove_location(params[:did])
        did, doc = local_retrieve_document(identifier)
        if doc.nil?
            render json: {"error": "cannot find " + identifier.to_s}.to_json,
                   status: 404
        else
            log_result = local_retrieve_log(did)
            render json: {"doc": doc, "log": log_result}.to_json,
                   status: 200
        end
    end

    def create
        # input
        input = params.except(:controller, :action)
        did = input["did"]
        didDocument = input["did-document"]
        logs = input["logs"]

        # validate input
        if did.nil? || did == {}
            render json: {"error": "missing DID"},
                   status: 400
            return
        end
        if did[0,8] != "did:oyd:"
            render json: {"error": "invalid DID"},
                   stauts: 412
            return
        end
        didLocation = did.split(LOCATION_PREFIX)[1] rescue ""
        didHash = did.split(LOCATION_PREFIX)[0] rescue did
        didHash = didHash.delete_prefix("did:oyd:")
        if !Did.find_by_did(didHash).nil?
            render json: {"message": "DID already exists"},
                   status: 200
            return
        end

        if didDocument.nil?
            render json: {"error": "missing did-document"},
                   status: 400
            return
        end
        didDoc = JSON.parse(didDocument.to_json) rescue nil
        if didDoc.nil?
            render json: {"error": "cannot parse did-document"},
                   status: 412
            return
        end
        # allow "doc": null
        # if didDoc["doc"].nil?
        #     render json: {"error": "missing 'doc' key in did-document"},
        #            status: 412
        #     return
        # end
        if didDoc["key"].nil?
            render json: {"error": "missing 'key' key in did-document"},
                   status: 412
            return
        end
        didPubKey = didDoc["key"].split(":").first rescue nil
        if didPubKey.nil?
            render json: {"error": "missing public document key in did-document"},
                   status: 412
            return
        end
        if didDoc["log"].nil?
            render json: {"error": "missing 'log' key in did-document"},
                   status: 412
            return
        end
        options = {}
        options[:digest] = Oydid.get_digest(didHash).first
        options[:encode] = Oydid.get_encoding(didHash).first
        if didHash != Oydid.multi_hash(Oydid.canonical(didDocument), options).first
            render json: {"error": "DID does not match did-document"},
                   status: 400
            return
        end

        if !logs.is_a? Array
            render json: {"error": "log is not an array"},
                   status: 412
            return
        end
        if logs.count < 2
            render json: {"error": "not enough log entries (min: 2)"},
                   status: 412
            return
        end
        log_entry_hash = ""
        logs.each do |item|
            case item["op"]
            when 0 # TERMINATE
                log_entry_hash = Oydid.multi_hash(Oydid.canonical(item), LOG_HASH_OPTIONS).first
            when 2, 3 # CREATE or UPDATE
                # check with didPubKey validity of signature
                if !Oydid.verify(item["doc"], item["sig"], didPubKey)
                    render json: {"error": "invalid signature in log with op=" + item["op"].to_s},
                           status: 400
                end
            end
        end
        if log_entry_hash != ""
            did_log = didDoc["log"].to_s
            did_log = did_log.split(LOCATION_PREFIX)[0] rescue did_log
            if did_log != log_entry_hash
                render json: {"error": "invalid 'log' key in did-document"},
                       status: 412
                return
            end
        end

        @did = Did.find_by_did(didHash)
        if @did.nil?
            Did.new(did: didHash, doc: didDocument.to_json, public_key: didPubKey).save
        end
        logs.each do |item|
            if item["op"] == 1 # REVOKE
                my_hash = Oydid.multi_hash(Oydid.canonical(item.except("previous")), LOG_HASH_OPTIONS).first
                @log = Log.find_by_oyd_hash(my_hash)
                if @log.nil?
                    Log.new(did: didHash, item: item.to_json, oyd_hash: my_hash, ts: Time.now.to_i).save
                end
            else
                my_hash = Oydid.multi_hash(Oydid.canonical(item), LOG_HASH_OPTIONS).first
                @log = Log.find_by_oyd_hash(my_hash)
                if @log.nil?
                    Log.new(did: didHash, item: item.to_json, oyd_hash: my_hash, ts: Time.now.to_i).save
                end
            end
        end

        render plain: "",
               stauts: 200
    end

    def delete
        options = {}
        did = params[:did].to_s
        didHash = did.split(LOCATION_PREFIX)[0] rescue did
        didHash = didHash.delete_prefix("did:oyd:")
        options[:digest] = Oydid.get_digest(didHash).first
        options[:encode] = Oydid.get_encoding(didHash).first

        @did = Did.find_by_did(didHash)
        if @did.nil?
            render json: {"error": "DID not found"},
                   status: 404
            return
        end
        keys = JSON.parse(@did.doc)["key"]
        public_doc_key = keys.split(":")[0]
        public_rev_key = keys.split(":")[1]
        private_doc_key = params[:dockey]
        private_rev_key = params[:revkey]
        if public_doc_key == Oydid.public_key(private_doc_key, options).first &&
           public_rev_key == Oydid.public_key(private_rev_key, options).first
                Log.where(did: didHash).destroy_all
                Did.where(did: didHash).destroy_all
                render plain: "",
                       status: 200
        else
            puts "Doc key: " + public_doc_key.to_s + " <=> " + Oydid.public_key(private_doc_key, {}).first.to_s
            puts "Rev key: " + public_rev_key.to_s + " <=> " + Oydid.public_key(private_rev_key, {}).first.to_s
            render json: {"error": "invalid keys"},
                   status: 403
        end
    end

    # Uniresolver functions =====================
    def resolve
        options = {}
        did = params[:did]
        didLocation = did.split(LOCATION_PREFIX)[1] rescue ""
        didHash = did.split(LOCATION_PREFIX)[0] rescue did
        didHash = didHash.delete_prefix("did:oyd:")
        options[:digest] = Oydid.get_digest(didHash).first
        options[:encode] = Oydid.get_encoding(didHash).first
        result = resolve_did(did, options)
        if result["error"] != 0
            render json: {"error": result["message"].to_s}.to_json,
                   status: result["error"]
        else
            w3c_did = Oydid.w3c(result, options)
            render plain: w3c_did.to_json,
                   mime_type: Mime::Type.lookup("application/ld+json"),
                   content_type: 'application/ld+json',
                   status: 200
        end
    end

    def legacy_resolve
        options = {}
        did = params[:did]
        didLocation = did.split(LOCATION_PREFIX)[1] rescue ""
        didHash = did.split(LOCATION_PREFIX)[0] rescue did
        didHash = didHash.delete_prefix("did:oyd:")
        options[:digest] = Oydid.get_digest(didHash).first
        options[:encode] = Oydid.get_encoding(didHash).first
        result = resolve_did(did, options)
        if result["error"] != 0
            render json: {"error": result["message"].to_s}.to_json,
                   status: result["error"]
        else
            w3c_did = Oydid.w3c_legacy(result, options)
            render plain: w3c_did.to_json,
                   mime_type: Mime::Type.lookup("application/ld+json"),
                   content_type: 'application/ld+json',
                   status: 200
        end
    end

    # Uniregistrar functions ====================

    # input
    # {
    #     "options": {
    #         "ledger": "test",
    #         "keytype": "ed25519"
    #     },
    #     "secret": {},
    #     "didDocument": {}
    # }
    def uniregistrar_create
        jobId = params[:jobId] rescue nil
        if jobId.nil?
            jobId = SecureRandom.uuid
        end
        didDocument = params[:didDocument]
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

        doc = didDocument
        did_obj = JSON.parse(doc.to_json) rescue nil
        if !did_obj.nil? && did_obj.is_a?(Hash)
            if did_obj["@context"] == "https://www.w3.org/ns/did/v1"
                doc = Oydid.fromW3C(didDocument, options)
            end
        end
        
        preprocessed = false
        msg = ""
        if !did_obj.nil? && did_obj.is_a?(Hash)
            if did_obj["doc"].to_s != "" && did_obj["key"].to_s != "" && did_obj["log"].to_s != ""
                if !options[:log_create].nil? && !options[:log_terminate].nil?
                    preprocessed = true

                    # perform sanity checks on input data
                    # is doc in log create record == Hash(did_document)
                    if Oydid.multi_hash(Oydid.canonical(did_obj), options).first != options[:log_create]["doc"]
                        render json: {"error": "invalid input data (create log does not match DID document)"},
                               status: 400
                        return
                    end

                    # check valid signature in log create record
                    doc_pubkey = did_obj["key"].split(":").first.to_s
                    success, msg = Oydid.verify(options[:log_create]["doc"], options[:log_create]["sig"], doc_pubkey)
                    if !success
                        render json: {"error": "invalid input data (create log has invalid signature)"},
                               status: 400
                        return
                    end

                    # check valid signature in terminate record
                    success, msg = Oydid.verify(options[:log_terminate]["doc"], options[:log_terminate]["sig"], doc_pubkey)
                    if !success
                        render json: {"error": "invalid input data (terminate log has invalid signature)"},
                               status: 400
                        return
                    end

                    # create DID
                    did = "did:oyd:" + Oydid.multi_hash(Oydid.canonical(did_obj), options).first
                    logs = [options[:log_create], options[:log_terminate]]
                    success, msg = Oydid.publish(did, did_obj, logs, options)
                    if success
                        w3c_input = {
                            "did" => did,
                            "doc" => didDocument
                        }
                        status = {
                            "did" => did,
                            "doc" => didDocument,
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
        end
        if !preprocessed
            status, msg = Oydid.create(doc, options)
        end
        if status.nil?
            render json: {"error": msg},
                   status: 500
        else
            retVal = {
                "didState": {
                    "did": Oydid.percent_encode(status["did"]),
                    "state": "finished",
                    "secret": {
                        "documentKey": status["private_key"],
                        "revocationKey": status["revocation_key"],
                        "revocationLog": status["revocation_log"]
                    },
                    "didDocument": status["doc_w3c"]
                },
                "didRegistrationMetadata": {},
                "didDocumentMetadata": {
                    "did": Oydid.percent_encode(status["did"]),
                    "registry": Oydid.get_location(status["did"].to_s),
                    "log_hash": status["doc"]["log"].to_s,
                    "log": status["log"]
                }
            }
            render json: retVal.to_json,
                   status: 200
        end
    end

    # input
    # {
    #     "identifier": "did:sov:WRfXPg8dantKVubE3HX8pw",
    #     "options": {
    #         "ledger": "test",
    #         "keytype": "ed25519"
    #     },
    #     "secret": {},
    #     "didDocument": {}
    # }
    def uniregistrar_update
        jobId = params[:jobId] rescue nil
        if jobId.nil?
            jobId = SecureRandom.uuid
        end
        old_did = params[:identifier]
        didDocument = params[:didDocument]

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

        did_obj = JSON.parse(didDocument.to_json) rescue nil
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
            retVal = {
                "didState": {
                    "did": Oydid.percent_encode(status["did"]),
                    "state": "finished",
                    "secret": {
                        "documentKey": status["private_key"],
                        "revocationKey": status["revocation_key"],
                        "revocationLog": status["revocation_log"]
                    },
                    "didDocument": status["doc_w3c"]
                },
                "didRegistrationMetadata": {},
                "didDocumentMetadata": {
                    "did": Oydid.percent_encode(status["did"]),
                    "registry": Oydid.get_location(status["did"].to_s),
                    "log_hash": status["doc"]["log"].to_s,
                    "log": status["log"]
                }
            }
            render json: retVal.to_json,
                   status: 200
        end
    end

    # input
    # {
    #     "identifier": "did:sov:WRfXPg8dantKVubE3HX8pw",
    #     "options": {
    #         "ledger": "test",
    #         "keytype": "ed25519"
    #     },
    #     "secret": {}
    # }
    def uniregistrar_deactivate
        jobId = params[:jobId] rescue nil
        if jobId.nil?
            jobId = SecureRandom.uuid
        end
        did = params[:identifier]
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
                "didState": {
                    "did": Oydid.percent_encode(did),
                    "state": "finished",
                },
                "didRegistrationMetadata": {},
                "didDocumentMetadata": {
                    "did": Oydid.percent_encode(status["did"]),
                    "registry": Oydid.get_location(status["did"].to_s)
                }
            }
            render json: retVal.to_json,
                   status: 200
        end
    end

    def init
        session_id = params[:session_id].to_s
        if session_id == ""
            render json: {"error": "missing session_id"},
                   status: 401
            return
        end
        public_key = params[:public_key].to_s
        if public_key == ""
            render json: {"error": "missing public_key"},
                   status: 401
            return
        end

        challenge = SecureRandom.alphanumeric(32)
        oauth_app_name = ENV["DEFAULT_VC_OAUTH_APP"].to_s
        @oauth_app = Doorkeeper::Application.find_by_name(oauth_app_name) rescue nil
        if @oauth_app.nil?
            render json: {"error": "OAuth not configured"},
                   status: 404
            return
        end
        DidSession.new(
            session: params[:session_id].to_s,
            public_key: params[:public_key].to_s,
            challenge: challenge,
            oauth_application_id: @oauth_app.id).save
        render json: {"challenge": challenge}, 
               status: 200
    end

    def token
        #input
        sid = params[:session_id].to_s
        signed_challenge = params[:signed_challenge].to_s

        # checks
        @ds = DidSession.find_by_session(sid)
        if @ds.nil?
            render json: {"error": "session_id not found"},
                   status: 404
            return
        end
        public_key = @ds.public_key.to_s
        @oauth = Doorkeeper::Application.find(@ds.oauth_application_id)
        if @oauth.nil?
            render json: {"error": "OAuth reference not found"},
                   status: 404
            return
        end

        verified, error_msg = Oydid.verify(@ds.challenge.to_s, signed_challenge, public_key)
        if !verified
            render json: {"error": "invalid signature"},
                   status: 403
            return
        end

        # create token
        @t = Doorkeeper::AccessToken.new(application_id: @oauth.id, expires_in: 7200, scopes: @oauth.scopes, public_key: public_key)
        if @t.save
            retVal = {
                "access_token": @t.token.to_s,
                "token_type": "Bearer",
                "expires_in": @t.expires_in,
                "scope": @t.scopes.to_s,
                "created_at": @t.created_at.to_i }
            @ds.destroy
            render json: retVal,
                   status: 200
        else
            render json: {"error": "cannot create access token - " + @t.errors.to_json},
                   status: 500
        end
    end
end