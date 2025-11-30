class CmsmController < ApplicationController
    include ApplicationHelper
    include ActionController::MimeResponds

    # respond only to JSON requests
    respond_to :json
    respond_to :html, only: []
    respond_to :xml, only: []

    def show
        pubkey = params[:id]
        @cmsm = Cmsm.find_by_pubkey(pubkey)
        if @cmsm.nil?
            render json: {error: "not found"},
                   status: 404
        else
            render json: @cmsm.payload,
                   status: 200
        end
    end

    def create
        input = params.except(:controller, :action)
        pubkey = params[:pubkey]
        payload = JSON.parse(params[:payload]) rescue nil

        if payload.nil?
            render json: {error: "invalid payload"},
                   status: 400
            return
        end

        @cmsm = Cmsm.find_by_pubkey(pubkey)
        if @cmsm.nil?
            @cmsm = Cmsm.new
        end

        @cmsm.pubkey = pubkey
        @cmsm.payload = payload.to_json
        @cmsm.save

        render json: {},
               status: 200

    end

end