class DidsController < ApplicationController
    include ApplicationHelper
    include ActionController::MimeResponds

    # respond only to JSON requests
    respond_to :json
    respond_to :html, only: []
    respond_to :xml, only: []


    def version
        render json: {"version": VERSION.to_s}.to_json,
               status: 200
    end

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
                    if Oydid.hash(Oydid.canonical(did_obj)) != options[:log_create]["doc"]
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
                    did = "did:oyd:" + Oydid.hash(Oydid.canonical(did_obj))
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
                "jobId": jobId,
                "didState": {
                    "identifier": status["did"],
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
                    "did": status["did"].to_s,
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
                did = "did:oyd:" + Oydid.hash(Oydid.canonical(did_obj))
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
                "jobId": jobId,
                "didState": {
                    "identifier": status["did"],
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
                    "did": status["did"].to_s,
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