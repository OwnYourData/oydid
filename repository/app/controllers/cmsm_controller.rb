class CmsmController < ApplicationController
    include ApplicationHelper
    include ActionController::MimeResponds

    # respond only to JSON requests
    respond_to :json
    respond_to :html, only: []
    respond_to :xml, only: []

    # Remote counterpart of LocalCmsmStore: holds the intermediate data of a
    # Client-Managed-Secret-Mode flow between phases. Records are addressed by
    # the session handle the oydid gem generates, not by the public key.

    def show
        Cmsm.sweep
        @cmsm = Cmsm.find_by_session(params[:id])
        if @cmsm.nil? || @cmsm.expired?
            render json: {error: "unknown or expired CMSM session"},
                   status: 404
        else
            render json: @cmsm.payload,
                   status: 200
        end
    end

    def create
        session = params[:session].to_s
        payload = JSON.parse(params[:payload]) rescue nil

        if session == ""
            render json: {error: "missing session"},
                   status: 400
            return
        end
        if payload.nil?
            render json: {error: "invalid payload"},
                   status: 400
            return
        end

        @cmsm = Cmsm.find_by_session(session) || Cmsm.new(session: session)
        @cmsm.session = session
        @cmsm.pubkey  = params[:pubkey]
        @cmsm.payload = payload.to_json
        @cmsm.save

        render json: {session: session},
               status: 200
    end
end
