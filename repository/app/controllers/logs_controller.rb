class LogsController < ApplicationController
include ApplicationHelper

    def show
        id = params[:id]
        location = id.split(LOCATION_PREFIX)[1] rescue ""
        id = id.split(LOCATION_PREFIX)[0] rescue id
        id = id.delete_prefix("did:oyd:")

        @log = Log.find_by_oyd_hash(id)
        if @log.nil?
            didHash = id
        else
            didHash = @log.did
        end
        logs = local_retrieve_log(didHash)

        render json: logs.sort_by { |el| el["ts"] }.to_json, 
               status: 200
    end

    def create
        did = params[:did]
        @log = Log.new(did: did, item: params[:log].to_json, oyd_hash: Oydid.hash(Oydid.canonical(params[:log])), ts: Time.now.to_i)
        if @log.save
            render plain: "", 
                   status: 200
        else
            render json: {"error": "failed to save log entry"},
                   status: 500
        end
    end

end