class DidsController < ApplicationController
    include ApplicationHelper
    include ApplicationHelperLegacy
    include ActionController::MimeResponds

    # respond only to JSON requests
    respond_to :json
    respond_to :html, only: []
    respond_to :xml, only: []

    def resolve
        options = {}
        did = params[:did]
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

        retVal = {
            "didResolutionMetadata":{},
            "didDocument": Oydid.w3c(result, {}),
            "didDocumentMetadata": {
                "did": "did:oyd:" + result["did"].to_s,
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
                equivalentIds << "did:oyd:" + log["doc"]
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

end