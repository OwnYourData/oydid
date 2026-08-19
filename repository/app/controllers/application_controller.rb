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
        render html: home_page.html_safe,
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

    private

    RESOLVER_EXAMPLE_DID = "did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh"

    # Start page with a did:oyd resolver. uniresolver.io no longer serves
    # did:oyd, so this offers the same resolution result (didDocument +
    # didResolutionMetadata + didDocumentMetadata) directly from this repository.
    #
    # The result is fetched client-side from /1.0/resolve/{did} and written with
    # textContent only - never innerHTML - so an identifier taken from the URL
    # fragment cannot inject markup.
    def home_page
        <<~HTML
          <!DOCTYPE html>
          <html lang="en">
          <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>OYDID - Own Your Decentralized Identifier</title>
          <style>
            :root { color-scheme: light dark; }
            * { box-sizing: border-box; }
            body { margin: 0; padding: 2rem 1.25rem 3rem;
                   font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                   color: #1c1e21; background: #fff; }
            main { max-width: 62rem; margin: 0 auto; }
            h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
            h2 { font-size: 1.05rem; margin: 2rem 0 .6rem; }
            .sub { color: #6b7076; margin: 0 0 1.75rem; }
            form { display: flex; gap: .5rem; flex-wrap: wrap; }
            input[type=text] { flex: 1 1 26rem; min-width: 0; padding: .6rem .7rem; font-size: .95rem;
                               font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                               border: 1px solid #c6cbd1; border-radius: 6px; background: #fff; color: inherit; }
            input[type=text]:focus { outline: 2px solid #2b6cb0; outline-offset: -1px; border-color: #2b6cb0; }
            button { padding: .6rem 1.1rem; font-size: .95rem; font-weight: 600; cursor: pointer;
                     border: 1px solid #2b6cb0; border-radius: 6px; background: #2b6cb0; color: #fff; }
            button:hover { background: #245a94; }
            button[disabled] { opacity: .6; cursor: progress; }
            .hint { color: #6b7076; font-size: .85rem; margin: .55rem 0 0; }
            .hint code { cursor: pointer; text-decoration: underline dotted; }
            .box { margin: 1.25rem 0 0; padding: .7rem .85rem; border-radius: 6px; display: none; }
            .box.err { display: block; background: #fdecea; border: 1px solid #f5c2bd; color: #8a1c11; }
            .box.ok  { display: block; background: #eef7ee; border: 1px solid #c3e2c4; color: #1f5124; }
            #result { display: none; }
            pre { margin: 0; padding: .85rem; overflow-x: auto; border: 1px solid #e1e4e8;
                  border-radius: 6px; background: #f7f8fa; font-size: .82rem; line-height: 1.45;
                  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
            footer { margin-top: 2.5rem; padding-top: 1.25rem; border-top: 1px solid #e1e4e8; }
            ul { padding-left: 1.2rem; } li { margin: .2rem 0; }
            a { color: #2b6cb0; }
            @media (prefers-color-scheme: dark) {
              body { background: #16181c; color: #e5e7eb; }
              input[type=text] { background: #1f2229; border-color: #3a3f47; }
              pre { background: #1b1e24; border-color: #3a3f47; }
              footer { border-color: #3a3f47; }
              .sub, .hint { color: #9aa1a9; }
              .box.err { background: #3a1d1a; border-color: #6b2f28; color: #f7b3ac; }
              .box.ok  { background: #17301c; border-color: #2f5c36; color: #a8dcae; }
              a { color: #7cb0e8; }
            }
          </style>
          </head>
          <body>
          <main>
            <h1>OYDID Resolver</h1>
            <p class="sub">Resolve a <code>did:oyd</code> identifier to its DID Document.</p>

            <form id="f">
              <input type="text" id="did" spellcheck="false" autocapitalize="off" autocorrect="off"
                     placeholder="did:oyd:zQm..." aria-label="DID to resolve">
              <button type="submit" id="go">Resolve</button>
            </form>
            <p class="hint">Example: <code id="ex">#{RESOLVER_EXAMPLE_DID}</code> &ndash; identifiers hosted on
               another repository (<code>&lt;did&gt;@&lt;location&gt;</code>) are resolved as well.</p>

            <div id="status" class="box"></div>

            <div id="result">
              <h2>DID Document</h2>
              <pre id="doc"></pre>
              <h2>DID Resolution Metadata</h2>
              <pre id="resmeta"></pre>
              <h2>DID Document Metadata</h2>
              <pre id="docmeta"></pre>
            </div>

            <footer>
              <h2>OYDID Repository</h2>
              <p>Version #{VERSION} (oydid gem v#{Gem.loaded_specs["oydid"].version})
                 &ndash; #{Did.count} DIDs, #{Log.count} log entries</p>
              <ul>
                <li>API documentation: <a href="/api-docs">Swagger</a></li>
                <li>Specification: <a href="https://ownyourdata.github.io/oydid/">ownyourdata.github.io/oydid</a></li>
                <li>Source: <a href="https://github.com/OwnYourData/oydid/">github.com/OwnYourData/oydid</a></li>
              </ul>
            </footer>
          </main>

          <script>
          (function () {
            var f = document.getElementById('f'),
                input = document.getElementById('did'),
                go = document.getElementById('go'),
                statusBox = document.getElementById('status'),
                result = document.getElementById('result'),
                out = { doc: document.getElementById('doc'),
                        resmeta: document.getElementById('resmeta'),
                        docmeta: document.getElementById('docmeta') };

            document.getElementById('ex').addEventListener('click', function () {
              input.value = this.textContent;
              resolve(this.textContent);
            });

            function show(kind, msg) {
              statusBox.className = 'box ' + kind;
              statusBox.textContent = msg;
            }

            function resolve(did) {
              did = (did || '').trim();
              if (!did) { return; }
              if (did.indexOf('did:oyd:') !== 0) { did = 'did:oyd:' + did.replace(/^did:[^:]+:/, ''); }
              input.value = did;
              if (decodeURIComponent(location.hash.slice(1)) !== did) {
                history.replaceState(null, '', '#' + did);
              }

              go.disabled = true;
              result.style.display = 'none';
              show('ok', 'Resolving ' + did + ' ...');

              fetch('/1.0/resolve/' + encodeURIComponent(did), { headers: { 'Accept': 'application/json' } })
                .then(function (r) { return r.json().then(function (b) { return { s: r.status, b: b }; },
                                                          function ()  { return { s: r.status, b: {} }; }); })
                .then(function (res) {
                  if (res.s === 200) {
                    out.doc.textContent = JSON.stringify(res.b.didDocument, null, 2);
                    out.resmeta.textContent = JSON.stringify(res.b.didResolutionMetadata, null, 2);
                    out.docmeta.textContent = JSON.stringify(res.b.didDocumentMetadata, null, 2);
                    result.style.display = 'block';
                    show('ok', 'Resolved successfully.');
                  } else if (res.s === 410) {
                    show('err', 'This DID has been revoked (HTTP 410). No DID Document is served for it.');
                  } else if (res.s === 404) {
                    show('err', 'Not found (HTTP 404) - no DID with this identifier.');
                  } else {
                    show('err', 'Resolution failed (HTTP ' + res.s + '): ' + ((res.b && res.b.error) || 'unknown error'));
                  }
                })
                .catch(function (e) { show('err', 'Request failed: ' + e.message); })
                .then(function () { go.disabled = false; });
            }

            f.addEventListener('submit', function (e) { e.preventDefault(); resolve(input.value); });
            window.addEventListener('hashchange', function () { resolve(decodeURIComponent(location.hash.slice(1))); });

            if (location.hash.length > 1) {
              var initial = decodeURIComponent(location.hash.slice(1));
              input.value = initial;
              resolve(initial);
            }
          })();
          </script>
          </body>
          </html>
        HTML
    end

end
