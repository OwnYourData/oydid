class CredentialsController < ApplicationController
    include ApplicationHelper
    include ActionController::MimeResponds

    before_action -> { doorkeeper_authorize! :read, :write, :admin }, only: :show_vc

    # respond only to JSON requests
    respond_to :json
    respond_to :html, only: []
    respond_to :xml, only: []

    def show_vc
        identifier = params[:id].to_s
        @cred = Credential.find_by_identifier(identifier)
        if @cred.nil?
            render json: {"error": "not found"},
                   status: 404
        else
            @at = Doorkeeper::AccessToken.find_by_token(doorkeeper_token.token)
            cs = JSON.parse(@cred.vc)["credentialSubject"] rescue nil
            if cs.nil?
                render json: {"error": "Unauthorized"},
                       status: 401
                return
            end
            holder = cs.transform_keys(&:to_s)["id"]
            pubKey, msg = Oydid.getPubKeyFromDID(holder)
            if pubKey == @at.public_key.to_s
                render json: @cred.vc,
                       status: 200
            else
                render json: {"error": "Unauthorized (invalid public key)"},
                       status: 401
            end
        end
    end

    def publish_vc
        identifier = params[:identifier].to_s rescue nil
        vc = params[:vc] rescue nil
        holder = params[:holder].to_s rescue nil

        @cred = Credential.find_by_identifier(identifier)
        if @cred.nil?
            @cred = Credential.new(
                identifier: identifier,
                vc: vc.to_json,
                holder: holder)
            success = @cred.save
        else
            success = @cred.update_attributes(
                identifier: identifier,
                vc: vc.to_json,
                holder: holder)
        end
        if success
            render json: {"identifier": identifier},
                   status: 200
        else
            render json: {"error": "publishing credential failed"},
                   status: 500
        end
    end

    def show_vp
        identifier = params[:id].to_s
        @pres = Presentation.find_by_identifier(identifier)
        if @pres.nil?
            render json: {"error": "not found"},
                   status: 404
        else
            render json: @pres.vp,
                       status: 200
        end
    end

    def publish_vp
        identifier = params[:identifier].to_s rescue nil
        vp = params[:vp] rescue nil
        holder = params[:holder].to_s rescue nil

        @pres = Presentation.find_by_identifier(identifier)
        if @pres.nil?
            @pres = Presentation.new(
                identifier: identifier,
                vp: vp.to_json,
                holder: holder)
            success = @pres.save
        else
            success = @pres.update_attributes(
                identifier: identifier,
                vp: vp.to_json,
                holder: holder)
        end
        if success
            render json: {"identifier": identifier},
                   status: 200
        else
            render json: {"error": "publishing presentation failed"},
                   status: 500
        end
    end
end