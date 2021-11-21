class DidsController < ApplicationController
    include ApplicationHelper
    include ActionController::MimeResponds

    # respond only to JSON requests
    respond_to :json
    respond_to :html, only: []
    respond_to :xml, only: []

    def resolve
        options = {}
        did = params[:did]
        result = resolve_did(did, options)
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
            "didDocument": w3c_did(result),
            "didDocumentMetadata": {
                "did": result["did"].to_s,
                "registry": get_location(result["did"].to_s),
                "log_hash": result["doc"]["log"].to_s,
                "log": result["log"],
                "document_log_id": result["doc_log_id"].to_i,
                "termination_log_id": result["termination_log_id"].to_i
            }
        }

        render plain: retVal.to_json,
               mime_type: Mime::Type.lookup("application/ld+json"),
               content_type: 'application/ld+json',
               status: 200
    end

end