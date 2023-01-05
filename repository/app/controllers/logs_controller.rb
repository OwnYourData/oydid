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
        my_hash = Oydid.multi_hash(Oydid.canonical(params[:log]), LOG_HASH_OPTIONS)
        if Log.find_by_oyd_hash(my_hash).nil?
            @log = Log.new(did: did, item: params[:log].to_json, oyd_hash: my_hash, ts: Time.now.to_i)
            if @log.save
                render plain: "", 
                       status: 200
            else
                render json: {"error": "failed to save log entry"},
                       status: 500
            end
        else
            render plain: "", 
                   status: 200
        end
    end

end