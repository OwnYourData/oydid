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

    def home
        render html: home_page.html_safe,
               status: 200
    end

    def version
        render json: {"service": "oydid uniresolver plugin", "version": VERSION.to_s, "oydid-gem": Gem.loaded_specs["oydid"].version.to_s}.to_json,
               status: 200
    end

    def missing
        render json: {"error": "invalid path"},
               status: 404
    end

    private

    # Landing page: this service answers machine requests only, so / points at
    # the API description, the method specification and the interactive
    # resolver instead of resolving anything itself.
    def home_page
        <<~HTML
          <!DOCTYPE html>
          <html lang="en">
          <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>OYDID DID Resolver</title>
          <style>
            :root { color-scheme: light dark; }
            * { box-sizing: border-box; }
            body { margin: 0; padding: 2rem 1.25rem 3rem;
                   font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                   color: #1c1e21; background: #fff; }
            main { max-width: 46rem; margin: 0 auto; }
            h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
            h2 { font-size: 1.05rem; margin: 2rem 0 .6rem; }
            .sub { color: #6b7076; margin: 0 0 1.75rem; }
            ul { padding-left: 1.2rem; margin: 0; }
            li { margin: .45rem 0; }
            .desc { color: #6b7076; }
            code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .88em; }
            footer { margin-top: 2.5rem; padding-top: 1.25rem; border-top: 1px solid #e1e4e8;
                     color: #6b7076; font-size: .88rem; }
            a { color: #2b6cb0; }
            @media (prefers-color-scheme: dark) {
              body { background: #16181c; color: #e5e7eb; }
              footer { border-color: #3a3f47; color: #9aa1a9; }
              .sub, .desc { color: #9aa1a9; }
              a { color: #7cb0e8; }
            }
          </style>
          </head>
          <body>
          <main>
            <h1>OYDID DID Resolver</h1>
            <p class="sub">HTTP(S) binding of the DID Resolution functions for the
               <code>did:oyd</code> method.</p>

            <h2>Endpoints</h2>
            <ul>
              <li><code>/1.0/identifiers/{did}</code> <span class="desc">&ndash; Universal Resolver
                  binding, always a DID Resolution Result</span></li>
              <li><code>/1.0/resolve/{did}</code> <span class="desc">&ndash; content negotiated
                  via <code>Accept</code></span></li>
              <li><code>/1.0/resolveRepresentation/{did}</code> <span class="desc">&ndash; DID Document
                  in a concrete representation</span></li>
              <li><code>/1.0/dereference/{didUrl}</code> <span class="desc">&ndash; DID URL with
                  fragment</span></li>
            </ul>

            <h2>Further information</h2>
            <ul>
              <li><a href="/api-docs">API documentation</a>
                  <span class="desc">&ndash; Swagger UI for the endpoints above</span></li>
              <li><a href="https://ownyourdata.github.io/oydid/">OYDID Method Specification</a>
                  <span class="desc">&ndash; ownyourdata.github.io/oydid</span></li>
              <li><a href="https://oydid.ownyourdata.eu/">Interactive resolver</a>
                  <span class="desc">&ndash; resolve a <code>did:oyd</code> identifier in the browser</span></li>
              <li><a href="https://github.com/OwnYourData/oydid/">Source code</a>
                  <span class="desc">&ndash; github.com/OwnYourData/oydid</span></li>
            </ul>

            <footer>
              Version #{VERSION} (oydid gem v#{Gem.loaded_specs["oydid"].version})
            </footer>
          </main>
          </body>
          </html>
        HTML
    end

end
