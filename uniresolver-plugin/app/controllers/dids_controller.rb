class DidsController < ApplicationController
    include ApplicationHelper
    include ApplicationHelperLegacy
    include ActionController::MimeResponds

    # respond only to JSON requests
    respond_to :json
    respond_to :html, only: []
    respond_to :xml, only: []

    def uniresolver_resolve
        did = params[:did]
        options = {}
        didLocation = did.split(LOCATION_PREFIX)[1] rescue ""
        didHash = did.split(LOCATION_PREFIX)[0] rescue did
        didHash = didHash.delete_prefix("did:oyd:")
        options[:digest] = Oydid.get_digest(didHash).first
        options[:encode] = Oydid.get_encoding(didHash).first
        options[:followAlsoKnownAs] = ENV['FOLLOW_ALSOKNOWNAS'].to_s.downcase != 'false'
        result = Oydid.read(did, options).first rescue nil
        if result.nil? || result["error"] != 0
            result = resolve_did_legacy(did, options)
        end
        if result.nil?
            render json: {"error": "not found"},
                   status: 404
            return
        end
        if result["error"] != 0
            render json: {"error": result["message"].to_s},
                   status: result["error"]
            return
        end

        didResolutionMetadata = {}
        if !ENV["UNIRESOLVER_DEBUG"].nil?
            didResolutionMetadata = {
              "contentType": "application/did+ld+json",
              "pattern": "^(did:oyd:.+)$",
              "driverUrl": "https://oydid-resolver.data-container.net/1.0/identifiers/$1",
              "duration": 1,
              "did": {
                "didString": did,
                "methodSpecificId": didHash,
                "method": "oyd"
              }
            }
        end

        keys = []
        # document key
        keys << {
            "kid": Oydid.percent_encode("did:oyd:" + result["did"].to_s) + '#key-doc',
            "kms": "local",
            "type": "Ed25519", 
            "publicKeyHex": Oydid.multi_decode(result["doc"]["key"].split(":").first).first.unpack('H*').first
        }

        # revocation key
        keys << {
            "kid": Oydid.percent_encode("did:oyd:" + result["did"].to_s) + '#key-rev',
            "kms": "local",
            "type": "Ed25519", 
            "publicKeyHex": Oydid.multi_decode(result["doc"]["key"].split(":").last).first.unpack('H*').first
        }

        oydid_W3C = Oydid.w3c(Marshal.load(Marshal.dump(result)), {})
        if oydid_W3C["id"].split(":").take(2).join(":") == "did:oyd"
            key_ids = {}
            key_doc = oydid_W3C["verificationMethod"].first
            code, length, digest = Multibases.unpack(key_doc[:publicKeyMultibase]).decode.to_s('ASCII-8BIT').unpack('CCa*')
            pubKeyOyd_bytes = Ed25519::VerifyKey.new(digest).to_bytes
            key_doc[:publicKeyMultibase] = Multibases.pack("base58btc", pubKeyOyd_bytes).to_s
            # key_doc["publicKeyHex"] = Oydid.multi_decode(result["doc"]["key"].split(":").first).first.unpack('H*').first
            key_ids[key_doc[:id]] = key_doc.transform_keys(&:to_s)

            key_rev = oydid_W3C["verificationMethod"].last
            code, length, digest = Multibases.unpack(key_rev[:publicKeyMultibase]).decode.to_s('ASCII-8BIT').unpack('CCa*')
            pubKeyOyd_bytes = Ed25519::VerifyKey.new(digest).to_bytes
            key_rev[:publicKeyMultibase] = Multibases.pack("base58btc", pubKeyOyd_bytes).to_s
            # key_rev["publicKeyHex"] = Oydid.multi_decode(result["doc"]["key"].split(":").last).first.unpack('H*').first
            key_ids[key_rev[:id]] = key_rev.transform_keys(&:to_s)
            oydid_W3C["verificationMethod"] = [key_doc, key_rev]

            if !oydid_W3C["authentication"].nil? && 
                oydid_W3C["authentication"].count == 1 &&
                oydid_W3C["authentication"].first.keys == ["id"]
                    auth_obj = key_ids[oydid_W3C["authentication"].first["id"]]
                    auth_obj["publicKeyHex"] = Multibases.unpack(auth_obj["publicKeyMultibase"]).decode.to_s('ASCII-8BIT').unpack('H*').first
                    auth_obj.delete("publicKeyMultibase")
                    oydid_W3C["authentication"] = [auth_obj]
            end
        end

        if result["did"].to_s.start_with?("did:oyd")
            did_identifier = Oydid.percent_encode(result["did"].to_s)
        else
            did_identifier = Oydid.percent_encode("did:oyd:" + result["did"].to_s)
        end
        retVal = {
            "didResolutionMetadata": didResolutionMetadata,
            "didDocument": oydid_W3C,
            "didDocumentMetadata": {
                "did": did_identifier,
                "keys": keys,
                "registry": Oydid.get_location(result["did"].to_s),
                "log_hash": result["doc"]["log"].to_s,
                "log": result["log"],
                "document_log_id": result["doc_log_id"].to_i,
                "termination_log_id": result["termination_log_id"].to_i
            }
        }
        equivalentIds = []
        result["log"].each do |log|
            if log["op"] == 2 || log["op"] == 3
                equivalentIds << Oydid.percent_encode("did:oyd:" + log["doc"])
            end
        end unless result["log"].nil?

        if equivalentIds.length > 1
            retVal[:didDocumentMetadata][:equivalentId] = equivalentIds
        end

        render plain: retVal.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: 'application/ld+json',
               status: 200
    end

    def resolve
        render plain: {"status": "in progress", "did": params[:did].to_s}.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: 'application/ld+json',
               status: 200

    end

    def resolve_representation
        render plain: {"status": "in progress", "did": params[:did].to_s}.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: 'application/ld+json',
               status: 200

    end

    def dereference
        render plain: {"status": "in progress", "did": params[:did].to_s}.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: 'application/ld+json',
               status: 200

    end

end