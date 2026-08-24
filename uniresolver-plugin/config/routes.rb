Rails.application.routes.draw do
    # --- Universal Resolver driver binding -------------------------------
    # always answers with a full DID Resolution Result
    match '1.0/identifiers/:did',            to: 'dids#uniresolver_resolve',    via: 'get', constraints: {did: /.*/}

    # --- DID Resolution abstract functions, HTTP(S) binding ---------------
    # content negotiated via the Accept header, see DidsController
    match '1.0/resolve/:did',                to: 'dids#resolve',                via: 'get', constraints: {did: /.*/}
    match '1.0/resolveRepresentation/:did',  to: 'dids#resolve_representation', via: 'get', constraints: {did: /.*/}
    match '1.0/dereference/:did',            to: 'dids#dereference',            via: 'get', constraints: {did: /.*/}

    # unversioned aliases (kept for backwards compatibility)
    match 'resolve/:did',                    to: 'dids#resolve',                via: 'get', constraints: {did: /.*/}
    match 'resolve_representation/:did',     to: 'dids#resolve_representation', via: 'get', constraints: {did: /.*/}
    match 'resolveRepresentation/:did',      to: 'dids#resolve_representation', via: 'get', constraints: {did: /.*/}
    match 'dereference/:did',                to: 'dids#dereference',            via: 'get', constraints: {did: /.*/}

    # administrative
    match '/version',   to: 'application#version', via: 'get'
    match ':not_found', to: 'application#missing', via: [:get, :post], :constraints => { :not_found => /.*/ }
end
