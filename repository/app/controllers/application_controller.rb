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
        headers['Access-Control-Allow-Origin'] = '*'
        headers['Access-Control-Allow-Methods'] = 'POST, GET, PUT, DELETE, OPTIONS'
        headers['Access-Control-Allow-Headers'] = 'Origin, Content-Type, Accept, Authorization, Token'
        headers['Access-Control-Max-Age'] = "1728000"
        headers['Access-Control-Expose-Headers'] = '*'
    end

    def home
        output = "<html><head><title>OYDID - Own Your Decentralized Identifier</title>"
        output +="</head><body>"
        output +="<h1>OYDID Repository</h1>"
        output +="<p>Version: " + VERSION.to_s + " (oydid gem v" + Gem.loaded_specs["oydid"].version.to_s + ")</p>"
        output +="<p><strong>Statistics</strong> for this repository:</p><ul>"
        output +="<li>DIDs: " + Did.count.to_s + "</li>"
        output +="<li>Logs: " + Log.count.to_s + "</li>"
        output +="</ul><p>Find more information here:</p><ul>"
        output +='<li>Swagger: <a href="/api-docs">OYDID API Documentation</a></li>'
        output +='<li>Specification: <a href="https://ownyourdata.github.io/soya/">https://ownyourdata.github.io/oydid/</a></li>'
        output +='<li>Github: <a href="https://github.com/OwnYourData/oydid/">https://github.com/OwnYourData/oydid/</a></li>'
        output +="</ul></body></html>" 
        render html: output.html_safe, 
               status: 200
    end

    def version
        render json: {"service": "oydid repository", "version": VERSION.to_s, "oydid-gem": Gem.loaded_specs["oydid"].version.to_s}.to_json,
               status: 200
    end

    def missing
        render json: {"error": "invalid path"},
               status: 404
    end

end
