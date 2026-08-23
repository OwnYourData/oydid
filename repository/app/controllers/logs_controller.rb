class LogsController < ApplicationController
include ApplicationHelper

    def show
        id = params[:id]
        location = id.split(LOCATION_PREFIX)[1] rescue ""
        id = id.split(LOCATION_PREFIX)[0] rescue id
        id = id.delete_prefix("did:oyd:")

        @log = Log.find_by_any_hash(id) rescue nil
        if @log.nil?
            didHash = id
        else
            didHash = @log.did
        end
        logs = local_retrieve_log(didHash)

        render json: logs.sort_by { |el| el["ts"] }.to_json, 
               status: 200
    end

    def show_item
        id = params[:id]
        @log = Log.find_by_any_hash(id) rescue nil
        if @log.nil?
            render json: {"error": "not found"},
                   status: 404
        else
            render json: JSON.parse(@log.item),
                   status: 200
        end
    end

    def create
        did = params[:did]
        did = did.split(LOCATION_PREFIX)[0] rescue did
        did = did.delete_prefix("did:oyd:")
        log_record = params[:log]
        entry_hash, sub_hash = Log.hashes_for(log_record, LOG_HASH_OPTIONS)
        my_hash = entry_hash
        if !Log.stored?(entry_hash, sub_hash)
            @log = Log.new(did: did, item: params[:log].to_json, oyd_hash: entry_hash,
                           sub_hash: sub_hash, ts: Time.now.to_i)
            if @log.save
                render json: {"log": my_hash}, 
                       status: 200
            else
                render json: {"error": "failed to save log entry"},
                       status: 500
            end
        else
            render json: {"log": my_hash}, 
                   status: 200
        end
    end
end