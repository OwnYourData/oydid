class DidsController < ApplicationController
    include ApplicationHelper
    include ActionController::MimeResponds

    # respond only to JSON requests
    respond_to :json
    respond_to :html, only: []
    respond_to :xml, only: []

    # input
    # {
    #     "jobId": null,
    #     "options": {
    #         "ledger": "test",
    #         "keytype": "ed25519"
    #     },
    #     "secret": {},
    #     "didDocument": {}
    # }
    def create
        jobId = params[:jobId] rescue nil
        if jobId.nil?
            jobId = SecureRandom.uuid
        end
        didDocument = params[:didDocument]
        internal_didDocument = [0]
        options = {}
        status = Oydid.create(internal_didDocument, nil, "create", options)

        retVal = {
            "jobId": jobId,
            "didState": {
                "identifier": status[:did],
                "state": "finished",
                "secret": {},
                "didDocument": status[:didoc_w3c]
            },
            "didRegistrationMetadata": {},
            "didDocumentMetadata": {}
        }
        render json: retVal.to_json,
               status: 200
    end

    # input
    # {
    #     "jobId": null,
    #     "identifier": "did:sov:WRfXPg8dantKVubE3HX8pw",
    #     "options": {
    #         "ledger": "test",
    #         "keytype": "ed25519"
    #     },
    #     "secret": {},
    #     "didDocument": {}
    # }
    def update
        jobId = params[:jobId]

        retVal = {
            "jobId": jobId,
            "didState": {
                "identifier": "did:example:0000000000123456",
                "state": "finished",
                "secret": {
                    "keys": [{
                        "id": "did:example:0000000000123456#key-1",
                        "type": "Ed25519VerificationKey2018",
                        "privateKeyJwk": {}
                    }]
                },
                "didDocument": {}
            },
            "didRegistrationMetadata": {},
            "didDocumentMetadata": {}
        }
        render json: retVal.to_json,
               status: 200
    end

    # input
    # {
    #     "jobId": null,
    #     "identifier": "did:sov:WRfXPg8dantKVubE3HX8pw",
    #     "options": {
    #         "ledger": "test",
    #         "keytype": "ed25519"
    #     },
    #     "secret": {}
    # }
    def deactivate
        jobId = params[:jobId]

        retVal = {
            "jobId": jobId,
            "didState": {
                "state": "finished"
            },
            "didRegistrationMetadata": {},
            "didDocumentMetadata": {}
        }
        render json: retVal.to_json,
               status: 200
    end
end