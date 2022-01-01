class DidsController < ApplicationController
    include ApplicationHelper
    include ResolveHelper
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
        result = resolve_did(did, options)
        if result["error"] != 0
            render json: {"error": result["message"].to_s},
                   status: result["error"]
        else
            render json: result["doc"],
                   status: 200
        end
    end

    def w3c_did(did_info)
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
        wd
    end

    def resolve
        options = {}
        did = params[:did]
        result = resolve_did(did, options)
        if result["error"] != 0
            render json: {"error": result["message"].to_s},
                   status: result["error"]
        else
            render plain: w3c_did(result).to_json,
                   mime_type: Mime::Type.lookup("application/ld+json"),
                   content_type: 'application/ld+json',
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
        if didDoc["doc"].nil?
            render json: {"error": "missing 'doc' key in did-document"},
                   status: 412
            return
        end
        if didDoc["key"].nil?
            render json: {"error": "missing 'key' key in did-document"},
                   status: 412
            return
        end
        if didDoc["log"].nil?
            render json: {"error": "missing 'log' key in did-document"},
                   status: 412
            return
        end
        if didHash != oyd_hash(oyd_canonical(didDocument))
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
            if item["op"] == 0 # TERMINATE
                log_entry_hash = oyd_hash(oyd_canonical(item))
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

        Did.new(did: didHash, doc: didDocument.to_json).save
        logs.each do |item|
            if item["op"] == 1 # REVOKE
                Log.new(did: didHash, item: item.to_json, oyd_hash: oyd_hash(oyd_canonical(item.except("previous")).to_s), ts: Time.now.to_i).save
            else
                Log.new(did: didHash, item: item.to_json, oyd_hash: oyd_hash(oyd_canonical(item).to_s), ts: Time.now.to_i).save
            end
        end

        render plain: "",
               stauts: 200
    end

    def delete
        @did = Did.find_by_did(params[:did].to_s)
        if @did.nil?
            render json: {"error": "DID not found"},
                   status: 404
            return
        end
        keys = JSON.parse(@did.doc)["key"]
        public_doc_key = keys.split(":")[0]
        public_rev_key = keys.split(":")[1]
        private_doc_key = Ed25519::SigningKey.new(oyd_decode(params[:dockey]))
        private_rev_key = Ed25519::SigningKey.new(oyd_decode(params[:revkey]))
        if public_doc_key == oyd_encode(private_doc_key.verify_key.to_bytes) &&
           public_rev_key == oyd_encode(private_rev_key.verify_key.to_bytes)
                Log.where(did: params[:did].to_s).destroy_all
                Did.where(did: params[:did].to_s).destroy_all
                render plain: "",
                       status: 200
        else
            render json: {"error": "invalid keys"},
                   status: 403
        end
    end

end