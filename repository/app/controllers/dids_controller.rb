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

        did = remove_location(params[:did])
        result = local_retrieve_document(did)
        if result.nil?
            render json: {"error": "cannot find " + did.to_s}.to_json,
                   status: 404
        else
            log_result = local_retrieve_log(did)
            render json: {"doc": result, "log": log_result}.to_json,
                   status: 200
        end
    end

    def resolve
        options = {}
        did = params[:did]
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
        if didHash != Oydid.hash(Oydid.canonical(didDocument))
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
                log_entry_hash = Oydid.hash(Oydid.canonical(item))
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
            Did.new(did: didHash, doc: didDocument.to_json).save
        end
        logs.each do |item|
            if item["op"] == 1 # REVOKE
                my_hash = Oydid.hash(Oydid.canonical(item.except("previous")))
                @log = Log.find_by_oyd_hash(my_hash)
                if @log.nil?
                    Log.new(did: didHash, item: item.to_json, oyd_hash: my_hash, ts: Time.now.to_i).save
                end
            else
                my_hash = Oydid.hash(Oydid.canonical(item))
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
        @did = Did.find_by_did(params[:did].to_s)
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
        if public_doc_key == Oydid.public_key(private_doc_key).first &&
           public_rev_key == Oydid.public_key(private_rev_key).first
                Log.where(did: params[:did].to_s).destroy_all
                Did.where(did: params[:did].to_s).destroy_all
                render plain: "",
                       status: 200
        else
            puts "Doc key: " + public_doc_key.to_s + " <=> " + Oydid.public_key(private_doc_key).first.to_s
            puts "Rev key: " + public_rev_key.to_s + " <=> " + Oydid.public_key(private_rev_key).first.to_s
            render json: {"error": "invalid keys"},
                   status: 403
        end
    end

end