class ApplicationController < ActionController::API
    before_action :cors_preflight_check
    after_action :cors_set_access_control_headers
    
    include ActionController::MimeResponds
    include ApplicationHelper

    def cors_preflight_check
        if request.method == 'OPTIONS'
            headers['Access-Control-Allow-Origin'] = '*'
            headers['Access-Control-Allow-Methods'] = 'POST, GET, PUT, DELETE, OPTIONS'
            headers['Access-Control-Allow-Headers'] = 'X-Requested-With, X-Prototype-Version, Token'
            headers['Access-Control-Max-Age'] = '1728000'
            headers['Access-Control-Expose-Headers'] = '*'

            render text: '', content_type: 'text/plain'
        end
    end

    def cors_set_access_control_headers
        # seems to set it 2x?!
        # headers['Access-Control-Allow-Origin'] = '*'
        # headers['Access-Control-Allow-Methods'] = 'POST, GET, PUT, DELETE, OPTIONS'
        # headers['Access-Control-Allow-Headers'] = 'Origin, Content-Type, Accept, Authorization, Token'
        # headers['Access-Control-Max-Age'] = "1728000"
        # headers['Access-Control-Expose-Headers'] = '*'
    end

    def version
        render json: {"service": "oydid uniresolver plugin", "version": VERSION.to_s, "oydid-gem": Gem.loaded_specs["oydid"].version.to_s}.to_json,
               status: 200
    end

    def missing
        render json: {"error": "invalid path"},
               status: 404
    end

end
